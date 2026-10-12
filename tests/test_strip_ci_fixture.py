"""GIT-5 fixture: head must pass; strip_to_wrong.sh must make this fail."""

from tools.strip_ci_fixture.add import add


def test_add_one_plus_one_is_two():
    assert add(1, 1) == 2
