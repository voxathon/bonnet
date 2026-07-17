"""
Modernized SQLite ORM library
Based on puchikarui (c) 2014 Le Tuan Anh
"""

import os
import sys
import sqlite3
import logging
import functools
from collections import namedtuple
from collections.abc import Mapping

__version__ = "0.1.0"

__all__ = [
    '__version__', 'Database', 'Schema', 'Table', 'DataSource', 'MemorySource',
    'QueryBuilder', 'ExecutionContext', 'TableContext',
    'escape_like', 'head_like', 'tail_like', 'contain_like',
    'buckmode', 'normal_mode', 'with_ctx', 'to_obj', 'update_obj',
]


_TRANSMAP = {'%': '@%', '_': '@_', '@': '@@'}


def escape_like(input_string: str, escape_char: str = '@') -> str:
    tranmap = {
        '%': escape_char + '%',
        '_': escape_char + '_',
        escape_char: escape_char + escape_char
    }
    new_str = []
    for c in input_string:
        if c in tranmap:
            new_str.append(tranmap[c])
        else:
            new_str.append(c)
    return ''.join(new_str)


def head_like(input_string: str, escape_char: str = '@') -> str:
    return escape_like(input_string, escape_char) + '%'


def tail_like(input_string: str, escape_char: str = '@') -> str:
    return '%' + escape_like(input_string, escape_char)


def contain_like(input_string: str, escape_char: str = '@') -> str:
    return '%' + escape_like(input_string, escape_char) + '%'


def buckmode(cur, cache_size: int = 80000000, journal_mode: str = "OFF") -> None:
    cur.execute(f"PRAGMA cache_size={cache_size}")
    cur.execute("PRAGMA temp_store=MEMORY")
    cur.execute("PRAGMA locking_mode=EXCLUSIVE")
    cur.execute(f"PRAGMA journal_mode={journal_mode}")


def normal_mode(cur) -> None:
    cur.execute("PRAGMA cache_size=2000")
    cur.execute("PRAGMA locking_mode = NORMAL")
    cur.execute("PRAGMA journal_mode=1")
    cur.execute("PRAGMA temp_store=0")


def update_obj(source, target, *fields, **field_map):
    source_dict = source.__dict__ if hasattr(source, '__dict__') else source
    if not fields:
        fields = source_dict.keys()
    for f in fields:
        target_f = f if f not in field_map else field_map[f]
        setattr(target, target_f, source_dict[f])


def to_obj(cls, obj_data=None, *fields, **field_map):
    obj_dict = obj_data.__dict__ if hasattr(obj_data, '__dict__') else obj_data
    if not fields:
        fields = obj_dict.keys()
    obj = cls()
    update_obj(obj_dict, obj, *fields, **field_map)
    return obj


def build_select(table, where: str = None, orderby: str = None,
                 limit: object = None, offset: object = None, columns=None) -> str:
    query = []

    if isinstance(columns, str):
        columns = columns.split()
    if isinstance(table, Table):
        if not columns:
            columns = table.columns
        table_name = table.name
    else:
        table_name = str(table)

    query.append("SELECT ")
    query.append(','.join(columns) if columns else '*')
    query.append(" FROM ")
    query.append(table_name)
    if where:
        query.append(" WHERE ")
        query.append(where)
    if orderby:
        query.append(" ORDER BY ")
        query.append(orderby)
    if limit:
        query.append(" LIMIT ")
        query.append(str(limit))
    if offset:
        query.append(" OFFSET ")
        query.append(str(offset))
    return ''.join(query)


def build_insert(table, values: tuple, columns=None) -> str:
    num_values = len(values)

    if isinstance(table, Table):
        table_name = table.name
        if not columns:
            columns = table.columns
    else:
        table_name = str(table)

    if isinstance(columns, str):
        columns = columns.split()

    placeholders = ','.join(['?'] * num_values)

    if columns:
        if num_values < len(columns):
            column_names = ','.join(columns[-num_values:])
        else:
            column_names = ','.join(columns)
        return f"INSERT INTO {table_name} ({column_names}) VALUES ({placeholders}) "
    else:
        return f"INSERT INTO {table_name} VALUES ({placeholders}) "


def build_update_record(table, where: str = '', columns=None) -> str:
    set_fields = []

    table_name = table.name if isinstance(table, Table) else str(table)
    if columns is None:
        columns = table.columns
    if isinstance(columns, str):
        columns = columns.split()

    for col in columns:
        set_fields.append(f"{col}=?")

    if where:
        return f"UPDATE {table_name} SET {', '.join(set_fields)} WHERE {where}"
    else:
        return f"UPDATE {table_name} SET {', '.join(set_fields)}"


def build_delete(table, where: str = None) -> str:
    table_name = table.name if isinstance(table, Table) else str(table)
    if where:
        return f"DELETE FROM {table_name} WHERE {where}"
    else:
        return f"DELETE FROM {table_name}"


def build_update(table, set_expr: str, where: str) -> str:
    table_name = table.name if isinstance(table, Table) else str(table)
    if not where or not where.strip():
        return f"UPDATE {table_name} SET {set_expr}"
    else:
        return f"UPDATE {table_name} SET {set_expr} WHERE {where}"


class Table:
    def __init__(self, name: str, *columns, data_source=None, proto=None,
                 id_cols=None, strict_mode: bool = False, **field_map):
        self._strict_mode = strict_mode
        self.name = name
        self.columns = []
        self.add_fields(*columns)
        self._data_source = data_source
        self._proto = proto
        if not id_cols:
            self._id_cols = []
        elif isinstance(id_cols, str):
            self._id_cols = id_cols.split()
        else:
            self._id_cols = list(id_cols)
        self._field_map = dict(field_map)

    def add_fields(self, *columns):
        self.columns.extend(columns)
        if self._strict_mode:
            try:
                namedtuple(self.name, self.columns, rename=False)
            except Exception:
                logging.getLogger(__name__).warning(
                    f"WARNING: Bad database design detected (Table: {self.name} ({self.columns}))"
                )
        self.template = namedtuple(self.name, self.columns, rename=True)
        return self

    @property
    def id_cols(self):
        return self._id_cols

    def set_id(self, *id_cols):
        self._id_cols.extend(id_cols)
        return self

    def set_proto(self, proto) -> 'Table':
        self._proto = proto
        return self

    def field_map(self, **field_map):
        self._field_map.update(field_map)
        return self

    def __repr__(self):
        return f"Table({repr(self.name)}, *{repr(self.columns)})"

    def __str__(self):
        return repr(self)

    def to_table(self, row_tuples, columns=None) -> list:
        return [self.to_obj(x, columns) for x in row_tuples]

    def to_row(self, row_tuple, template=None) -> object:
        if template:
            return template(*row_tuple)
        else:
            return self.template(*row_tuple)

    def to_obj(self, row_tuple, columns=None) -> object:
        if not self._proto:
            if columns:
                new_tuples = namedtuple(self.name, columns, rename=True)
                return self.to_row(row_tuple, new_tuples)
            else:
                return self.to_row(row_tuple)

        if not columns:
            columns = self.columns
        new_obj = to_obj(self._proto, dict(zip(columns, row_tuple)), *columns, **self._field_map)
        return new_obj

    def ctx(self, ctx) -> object:
        return TableContext(self, ctx)

    def _ds_ctx(self):
        return getattr(self._data_source, self.name)

    def select_single(self, where=None, values=None, orderby=None, limit=None, columns=None, ctx=None):
        ctx = self._ds_ctx() if ctx is None else self.ctx(ctx)
        return ctx.select_single(where=where, values=values, orderby=orderby, limit=limit, columns=columns)

    def select(self, where=None, values=None, orderby=None, limit=None, offset=None, columns=None, ctx=None):
        ctx = self._ds_ctx() if ctx is None else self.ctx(ctx)
        return ctx.select(where, values, orderby=orderby, limit=limit, offset=offset, columns=columns)

    def select_iter(self, where=None, values=None, orderby=None, limit=None, offset=None, columns=None, ctx=None):
        ctx = self._ds_ctx() if ctx is None else self.ctx(ctx)
        return ctx.select_iter(where, values, orderby=orderby, limit=limit, offset=offset, columns=columns)

    def insert(self, *values, columns=None, ctx=None):
        ctx = self._ds_ctx() if ctx is None else self.ctx(ctx)
        return ctx.insert(*values, columns=columns)

    def delete(self, where=None, values=None, ctx=None):
        ctx = self._ds_ctx() if ctx is None else self.ctx(ctx)
        return ctx.delete(where=where, values=values)

    def delete_obj(self, obj, ctx=None):
        ctx = self._ds_ctx() if ctx is None else self.ctx(ctx)
        return ctx.delete_obj(obj)

    def update(self, set_expr: str, where='', values=None, ctx=None):
        ctx = self._ds_ctx() if ctx is None else self.ctx(ctx)
        return ctx.update(set_expr, where=where, values=values)

    def update_record(self, new_values, where='', where_values=None, columns=None, ctx=None):
        ctx = self._ds_ctx() if ctx is None else self.ctx(ctx)
        ctx.update_record(new_values, where, where_values, columns)

    def by_id(self, *args, columns=None, ctx=None):
        ctx = self._ds_ctx() if ctx is None else self.ctx(ctx)
        return ctx.by_id(*args, columns=columns)

    def save(self, obj, columns=None, ctx=None):
        ctx = self._ds_ctx() if ctx is None else self.ctx(ctx)
        return ctx.save(obj, columns)


class DataSource:
    def __init__(self, db_path: str, schema=None, auto_expand_path: bool = True):
        self.auto_expand_path = auto_expand_path
        self.path = db_path
        self._script_file_map = {}
        self.schema = schema
        self.__default_ctx_obj = None

    def __del__(self):
        if self.__default_ctx_obj is not None:
            self.__default_ctx_obj.close()

    @property
    def path(self):
        return self._filepath

    @path.setter
    def path(self, value):
        if value and str(value).startswith('~') and self.auto_expand_path:
            self._filepath = os.path.expanduser(value)
        else:
            self._filepath = value

    def _read_file(self, path: str) -> str:
        if path not in self._script_file_map:
            with open(path, 'r') as script_file:
                self._script_file_map[path] = script_file.read()
        return self._script_file_map[path]

    def _setup(self, exe: 'ExecutionContext', schema) -> None:
        logging.getLogger(__name__).warning(
            f"DB does not exist at {self.path}. Setup is required."
        )
        if schema is not None and schema.setup_files:
            for file_path in schema.setup_files:
                logging.getLogger(__name__).debug(f"Executing script file: {file_path}")
                exe.cur.executescript(self._read_file(file_path))
        if schema is not None and schema.setup_scripts:
            for script in schema.setup_scripts:
                exe.cur.executescript(script)

    def open(self, auto_commit=None, schema=None, **kwargs):
        if schema is None:
            schema = self.schema
        if auto_commit is None and schema is not None:
            auto_commit = schema.auto_commit
        exe = ExecutionContext(self.path, schema=schema, auto_commit=auto_commit)

        if self.path and (str(self.path) == ':memory:' or
                          not os.path.isfile(self.path) or os.path.getsize(self.path) == 0):
            self._setup(exe, schema)
        return exe

    def _default_ctx(self):
        if self.__default_ctx_obj is None:
            self.__default_ctx_obj = self.open()
        return self.__default_ctx_obj

    def __getattr__(self, name):
        _ctx = self._default_ctx()
        return getattr(_ctx, name)


class MemorySource(DataSource):
    def __init__(self, db_path: str, *args, **kwargs):
        super().__init__(db_path, *args, **kwargs)
        self.__conn = None

    def open(self, auto_commit=None, schema=None, force_iterdump: bool = False, **kwargs):
        if schema is None:
            schema = self.schema
        if auto_commit is None and schema is not None:
            auto_commit = schema.auto_commit

        if self.__conn is None:
            logging.getLogger(__name__).info(
                f"Fetching database into :memory: from file [{self.path}]"
            )
            source = sqlite3.connect(str(self.path))
            self.__conn = sqlite3.connect(":memory:")

            if sys.version_info < (3, 7) or force_iterdump:
                __cur = self.__conn.cursor()
                __cur.execute("PRAGMA synchronous=OFF")
                buckmode(__cur)
                for line in source.iterdump():
                    __cur.execute(line)
            else:
                source.backup(self.__conn)
            source.close()

        return ExecutionContext(self.__conn, schema=schema, auto_commit=auto_commit)


class QueryBuilder:
    def __init__(self, schema):
        self.schema = schema

    @classmethod
    def build_select(cls, table, where: str = None, orderby: str = None,
                     limit: object = None, offset: object = None, columns=None) -> str:
        return build_select(table, where, orderby, limit, offset, columns)

    @classmethod
    def build_insert(cls, table, values: tuple, columns=None) -> str:
        return build_insert(table, values, columns)

    @classmethod
    def build_update_record(cls, table, where: str = '', columns=None) -> str:
        return build_update_record(table, where, columns)

    @classmethod
    def build_delete(cls, table, where: str = None) -> str:
        return build_delete(table, where)

    @classmethod
    def build_update(cls, table, set_expr: str, where: str) -> str:
        return build_update(table, set_expr, where)


class TableContext:
    def __init__(self, table: Table, context: 'ExecutionContext'):
        self._table = table
        self._context = context

    def to_table(self, *args, **kwargs):
        return self._table.to_table(*args, **kwargs)

    def select(self, where=None, values=None, **kwargs):
        return self._context.select(self._table, where, values, **kwargs)

    def select_iter(self, where=None, values=None, **kwargs):
        return self._context.select_iter(self._table, where, values, **kwargs)

    def select_single(self, where=None, values=None, **kwargs):
        result = next(self._context.select_iter(self._table, where, values, **kwargs), None)
        return result

    def insert(self, *values, columns=None):
        return self._context.insert_record(self._table, values, columns)

    def update_record(self, new_values, where: str = '', where_values=None, columns=None):
        return self._context.update_record(self._table, new_values, where, where_values, columns)

    def delete(self, where: str = None, values=None):
        return self._context.delete_record(self._table, where, values)

    def by_id(self, args, columns=None):
        return self._context.select_object_by_id(self._table, args, columns)

    def save(self, obj, columns=None):
        existed = len(self._table._id_cols) > 0
        for i in self._table._id_cols:
            existed = existed and getattr(obj, i)
        if existed:
            return self._context.update_object(self._table, obj, columns, self._table._field_map)
        else:
            return self._context.insert_object(self._table, obj, columns, self._table._field_map)

    def delete_obj(self, obj):
        return self._context.delete_object(self._table, obj)

    def update(self, set_expr: str, where: str = '', values=None):
        return self._context.update(self._table, set_expr, where=where, values=values)


class ExecutionContext:
    def __init__(self, source, schema, auto_commit: bool = True, row_factory=sqlite3.Row):
        if isinstance(source, sqlite3.Connection):
            self.conn = source
        else:
            self.conn = sqlite3.connect(str(source))
        if row_factory is not None:
            self.conn.row_factory = row_factory
        self.cur = self.conn.cursor()
        self.schema = schema
        self.auto_commit = auto_commit
        self.__buckmode = False
        self.__closed = False

    def double(self, **kwargs):
        return ExecutionContext(self.conn, self.schema, **kwargs)

    @property
    def is_open(self):
        return not self.__closed

    def buckmode(self, cache_size: int = 80000000, journal_mode: str = "OFF") -> 'ExecutionContext':
        buckmode(self.cur, cache_size=cache_size, journal_mode=journal_mode)
        self.__buckmode = True
        return self

    def buckmode_off(self) -> 'ExecutionContext':
        normal_mode(self.cur)
        self.__buckmode = False
        return self

    def begin(self) -> None:
        self.execute("BEGIN")

    def rollback(self) -> None:
        self.conn.rollback()

    def commit(self) -> None:
        if self.is_open and self.conn is not None:
            self.conn.commit()
        else:
            raise sqlite3.OperationalError("Connection was closed. commit() failed")

    def vacuum(self) -> None:
        self.execute("VACUUM;")

    def select(self, table, where: str = None, values=None, orderby: str = None,
               limit: object = None, offset: object = None, columns=None):
        if isinstance(table, Table):
            return tuple(x for x in self.select_iter(table, where, values, orderby, limit, offset, columns))
        else:
            query = build_select(table, where, orderby, limit, offset, columns)
            return self.execute(query, values).fetchall()

    def select_iter(self, table, where: str = None, values=None, orderby: str = None,
                    limit: object = None, offset: object = None, columns=None):
        query = build_select(table, where, orderby, limit, offset, columns)
        if isinstance(table, Table):
            for row_tuple in self.execute(query, values):
                yield table.to_obj(row_tuple, columns=columns)
        else:
            return self.execute(query, values)

    def insert(self, table, values=None, columns=None, **kwargs):
        if values is None:
            values = kwargs
        if isinstance(values, Mapping):
            if kwargs:
                values.update(kwargs)
            if columns is None:
                columns = values.keys()
            values = tuple(values.values())
        query = build_insert(table, values, columns)
        self.execute(query, values)
        return self.cur.lastrowid

    def insert_record(self, table, values: tuple, columns=None) -> object:
        return self.insert(table, values, columns)

    def update_record(self, table, new_values: tuple, where: str = '', where_values: tuple = None, columns=None):
        query = build_update_record(table, where, columns)
        return self.execute(query, new_values + where_values if where_values else new_values)

    def delete_record(self, table, where: str = None, values=None):
        query = build_delete(table, where)
        return self.execute(query, values)

    def select_object_by_id(self, table: Table, ids: tuple, columns=None) -> object:
        _id_cols = table._id_cols if table._id_cols else ['rowid']
        where = ' AND '.join([f'{c}=?' for c in _id_cols])
        return next(self.select_iter(table, where, ids, columns=columns), None)

    def insert_object(self, table: Table, obj_data, columns=None, field_map: dict = None):
        if not columns and isinstance(table, Table):
            columns = table.columns
        values = tuple(
            getattr(obj_data, field_map[colname] if field_map and colname in field_map else colname)
            for colname in columns
        )
        self.insert_record(table, values, columns)
        return self.cur.lastrowid

    def update_object(self, table: Table, obj_data, columns=None, field_map: dict = None):
        where = ' AND '.join([f'{c}=?' for c in table._id_cols])
        where_values = tuple(getattr(obj_data, colname) for colname in table._id_cols)
        if not columns:
            columns = table.columns
        new_values = tuple(
            getattr(obj_data, field_map[colname] if field_map and colname in field_map else colname)
            for colname in columns
        )
        self.update_record(table, new_values, where, where_values, columns)

    def delete_object(self, table: Table, obj_data):
        where = ' AND '.join([f'{c}=?' for c in table._id_cols])
        where_values = tuple(getattr(obj_data, colname) for colname in table._id_cols)
        self.delete_record(table, where, where_values)

    def query_row(self, query: str, params=None) -> object:
        return self.execute(query, params).fetchone()

    def query_all(self, query: str, params=None) -> object:
        return self.execute(query, params).fetchall()

    def query_scalar(self, query: str, params=None) -> object:
        return self.query_row(query, params)[0]

    def update(self, table, set_expr: str, where: str = '', values=None):
        query = build_update(table, set_expr, where=where)
        return self.execute(query, values)

    def execute(self, query: str, params=None) -> object:
        try:
            if params:
                _r = self.cur.execute(query, params)
            else:
                _r = self.cur.execute(query)
            if not self.__buckmode and self.auto_commit:
                self.commit()
            return _r
        except Exception:
            logging.getLogger(__name__).exception(f'Query failed: q={query}, p={params}')
            raise

    def executescript(self, query: str) -> object:
        _r = self.cur.executescript(query)
        if not self.__buckmode and self.auto_commit:
            self.commit()
        return _r

    def executefile(self, file_loc: str) -> object:
        with open(file_loc, 'r') as script_file:
            script_text = script_file.read()
            return self.executescript(script_text)

    def close(self) -> None:
        if self.is_open:
            if self.auto_commit:
                self.commit()
            self.conn.close()
            self.conn = None
            self.__closed = True

    def __getattr__(self, name):
        if name in self.schema._tables:
            tbl = getattr(self.schema, name)
            ctx = TableContext(tbl, self)
            setattr(self, name, ctx)
            return getattr(self, name)
        elif name in dir(self.schema):
            return getattr(self.schema, name, None)
        else:
            raise AttributeError(f'Attribute {name} does not exist')

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.is_open:
            self.close()


class Database:
    def __init__(self, data_source=':memory:', setup_script: str = None,
                 setup_file: str = None, auto_commit: bool = True,
                 auto_expand_path: bool = True, strict_mode: bool = False):
        if not data_source:
            data_source = ':memory:'
        if isinstance(data_source, DataSource):
            self.__data_source = data_source
            self.__data_source.auto_commit = auto_commit
            self.__data_source.schema = self
        else:
            self.__data_source = DataSource(db_path=data_source, schema=self,
                                            auto_expand_path=auto_expand_path)
        self.auto_commit = auto_commit
        self.setup_files = []
        if setup_file:
            self.setup_files.append(setup_file)
        self.setup_scripts = []
        if setup_script:
            self.setup_scripts.append(setup_script)
        self._tables = {}
        self.query_builder = QueryBuilder(self)
        self._strict_mode = strict_mode

    @property
    def tables(self):
        return self._tables

    def add_file(self, setup_file: str) -> 'Database':
        self.setup_files.append(setup_file)
        return self

    def add_script(self, setup_script: str) -> 'Database':
        self.setup_scripts.append(setup_script)
        return self

    def add_table(self, name: str, columns=None, proto=None,
                  id_cols=None, alias: str = None, **field_map):
        if not columns:
            columns = []
        elif isinstance(columns, str):
            columns = columns.split()

        tbl_obj = Table(name, *columns, data_source=self.__data_source,
                        proto=proto, id_cols=id_cols, strict_mode=self._strict_mode,
                        **field_map)
        setattr(self, name, tbl_obj)
        self._tables[name] = tbl_obj
        if alias:
            setattr(self, alias, tbl_obj)
            self._tables[alias] = tbl_obj
        return tbl_obj

    @property
    def ds(self):
        return self.__data_source

    def ctx(self) -> 'ExecutionContext':
        return self.ds.open(schema=self)

    def __getattr__(self, name):
        return getattr(self.__data_source, name)


Schema = Database


def with_ctx(func=None):
    """Auto create a new context if not available"""
    @functools.wraps(func)
    def func_with_context(_obj, *args, **kwargs):
        if 'ctx' not in kwargs or kwargs['ctx'] is None:
            with _obj.ctx() as new_ctx:
                kwargs['ctx'] = new_ctx
                return func(_obj, *args, **kwargs)
        else:
            return func(_obj, *args, **kwargs)
    return func_with_context
