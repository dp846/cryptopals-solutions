import pytest
from src.task04 import read_file_into_lines, find_encrypted_line
from src.task03 import *

@pytest.fixture
def sample_file(tmpdir):
    """Creates a sample file for testing."""
    data = """
    hello
    world
    """
    file_path = tmpdir.join("sample.txt")
    file_path.write(data)
    return file_path

@pytest.fixture
def encrypted_lines_file(tmpdir):
    """Creates a sample file for testing."""
    data = """
    213a175ff30855e4001b305000263f5a5c3c5100163cee00114e3518f33a
    10ed33e65b003012e7131e161d5e2e270b4645f358394118330f5a5b241b
    33e80130f45708395457573406422a3b0d03e6e5053d0d2d151c083337a2
    551be2082b1563c4ec2247140400124d4b6508041b5a472256093aea1847
    7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f
    0864eb4935144c501103a71851370719301bec57093a0929ea3f18060e55
    2d395e57143359e80efffb13330633ea19e323077b4814571e5a3de73a1f
    52e73c1d53330846243c422d3e1b374b5209543903e3195c041c251b7c04
    2f3c2c28273a12520b482f18340d565d1fe84735474f4a012e1a13502523
    """
    file_path = tmpdir.join("encrypted.txt")
    file_path.write(data)
    return file_path


def test_read_file_into_lines(sample_file):
    lines = read_file_into_lines(sample_file)
    assert lines == ["hello", "world"]

def test_find_encrypted_line(encrypted_lines_file):
    result = find_encrypted_line(encrypted_lines_file)
    assert result[1] == 'Now that the party is jumping\n'

def test_read_non_existent_file():
    with pytest.raises(FileNotFoundError, match="No such file or directory"):
        read_file_into_lines('non_existent_file.txt')