# -*- coding: utf-8 -*-

"""Benchmark insert and select"""

import io
from pathlib import Path
from itertools import cycle
import timeit
import cProfile
import pstats

from orm import __version__
from orm import Database

DB_PATH = Path("test/data/test_benchmark.db")
SETUP_SCRIPT = """
CREATE TABLE person(
       ID INTEGER PRIMARY KEY AUTOINCREMENT,
       name TEXT NOT NULL,
       age INTEGER
);
CREATE TABLE hobby (
     pid INTEGER NOT NULL,
     hobby TEXT,
     FOREIGN KEY (pid) REFERENCES person(ID) ON DELETE CASCADE ON UPDATE CASCADE
);
"""


class SchemaDemo(Database):
    def __init__(
        self, data_source=":memory:", setup_script=SETUP_SCRIPT, *args, **kwargs
    ):
        Database.__init__(self, data_source=data_source, setup_script=setup_script)
        self.add_table("person", ["ID", "name", "age"], proto=Person, id_cols=("ID",))
        self.add_table("hobby").add_fields("pid", "hobby")


class Person(object):
    def __init__(self, name="", age=-1):
        self.ID = None
        self.name = name
        self.age = age

    def __str__(self):
        return "#{}: {}/{}".format(self.ID, self.name, self.age)

    def to_dict(self):
        return {"ID": self.ID, "name": self.name, "age": self.age}


def setup_db():
    if DB_PATH.is_file():
        DB_PATH.unlink()
    db = SchemaDemo(str(DB_PATH))
    return db


_db = None


def benchmark1(row_count=10000, db=None):
    global _db
    if db is None:
        db = _db
    db.person.delete()
    db.buckmode()
    for idx, name_seed in zip(range(row_count), cycle(range(65, 91))):
        name = f"Person {chr(name_seed)}{idx}"
        age = idx % 70
        db.person.save(Person(name, age))
    db.commit()
    persons = db.person.select()
    names = {p.name for p in persons}
    for n in names:
        db.person.select("name=?", (n,))


def _timeit():
    global _db
    _db = setup_db()
    repeat = 5
    t = timeit.timeit(lambda: benchmark1(db=_db), number=repeat)
    print(f"timeit ({repeat} times): {t} secs | avg: {t / repeat} secs")


def profile_it(benchmark_func, sort_fields=["cumulative", "filename", "ncalls"]):
    pr = cProfile.Profile()
    pr.enable()
    benchmark_func()
    pr.disable()
    s = io.StringIO()
    ps = pstats.Stats(pr, stream=s)
    if sort_fields:
        ps.sort_stats(*sort_fields)
    ps.print_stats()
    lines = s.getvalue().splitlines()
    return lines


if __name__ == "__main__":
    print(f"Benchmarking orm version {__version__}")
    _db = setup_db()
    lines = profile_it(lambda: benchmark1(db=_db))
    parent = Path(__file__).absolute().parent
    for idx, l in enumerate(lines):
        if idx >= 6 and "orm" not in l:
            continue
        print(l.replace(str(parent), parent.name))
    _timeit()
    print(f"Benchmarking orm version {__version__}")
