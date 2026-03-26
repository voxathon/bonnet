import pytest
import os
import time
from engine.ame import Ame, Board, Post
from core.crypto import Identity
from core.orm import Database

@pytest.fixture
def ame_setup(temp_dir):
    ame_path = os.path.join(temp_dir, 'ame')
    nav_db_path = os.path.join(temp_dir, 'nav.db')
    ident = Identity.generate()
    ame = Ame(ame_path, origin='test_origin', signing_key=ident.signing_key, nav_db_path=nav_db_path)
    yield ame, ident
    ame.shutdown()

def test_ame_create_board(ame_setup):
    ame, ident = ame_setup
    pubkey = Identity.generate().public_key
    board = ame.create_board("testboard", owner_pubkey=pubkey)
    assert board is not None
    assert ame.get_board("testboard") is board

    # check that the nav db correctly mapped the board to the owner pubkey
    owner = ame.get_board_owner("testboard")
    assert owner == pubkey

def test_ame_delete_board(ame_setup):
    ame, ident = ame_setup
    pubkey = Identity.generate().public_key
    board = ame.create_board("testboard2", owner_pubkey=pubkey)

    with pytest.raises(RuntimeError, match="Board must be closed before deletion"):
        ame.delete_board("testboard2")

    ame.close_board("testboard2")
    ame.delete_board("testboard2")

    assert ame.get_board("testboard2") is None
    assert ame.get_board_owner("testboard2") is None

def test_ame_list_boards(ame_setup):
    ame, ident = ame_setup
    pubkey = Identity.generate().public_key
    ame.create_board("board1", owner_pubkey=pubkey)
    ame.create_board("board2", owner_pubkey=pubkey)

    boards = ame.list_boards()
    assert len(boards) == 2
    board_names = [b[0] for b in boards]
    assert "board1" in board_names
    assert "board2" in board_names

def test_board_post_crud(ame_setup):
    ame, ident = ame_setup
    pubkey = Identity.generate().public_key
    board = ame.create_board("postboard", owner_pubkey=pubkey)

    # Create Post
    create_result = board.create_post(
        subject="Hello World",
        content="This is my first post.",
        author="alice",
        author_registrar="test_origin",
        tags="hello,test"
    )
    post = create_result.result(timeout=5)

    assert post is not None
    assert post.post_num == 1
    assert post.subject == "Hello World"
    assert post.content == "This is my first post."
    assert post.author == "alice"
    assert post.tags == "hello,test"

    # Get Post
    get_result = board.get_post(1)
    fetched_post = get_result.result(timeout=5)
    assert fetched_post is not None
    assert fetched_post.subject == "Hello World"
    assert fetched_post.content == "This is my first post."

    # Update Post
    update_result = board.update_post(1, {"subject": "Updated Hello World", "content": "Updated content."})
    assert update_result.result(timeout=5) is True

    get_result_updated = board.get_post(1)
    updated_post = get_result_updated.result(timeout=5)
    assert updated_post is not None
    assert updated_post.subject == "Updated Hello World"
    assert updated_post.content == "Updated content."

    # Delete Post
    delete_result = board.delete_post(1)
    assert delete_result.result(timeout=5) is True

    get_result_deleted = board.get_post(1)
    assert get_result_deleted.result(timeout=5) is None

def test_board_post_query(ame_setup):
    ame, ident = ame_setup
    pubkey = Identity.generate().public_key
    board = ame.create_board("queryboard", owner_pubkey=pubkey)

    board.create_post(subject="Post 1", author="alice", tags="first").result(timeout=5)
    board.create_post(subject="Post 2", author="bob", tags="second").result(timeout=5)
    board.create_post(subject="Post 3", author="alice", tags="third").result(timeout=5)

    query_result = board.query(where="author=?", values=["alice"], orderby="post_num ASC")
    posts = query_result.result(timeout=5)

    assert len(posts) == 2
    assert posts[0].subject == "Post 1"
    assert posts[1].subject == "Post 3"
