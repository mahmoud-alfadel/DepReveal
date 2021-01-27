from dependency_threat.helper.step1 import (
    get_commits,
    get_package_dependencies,
    fetch_dependency_history,
)
import pandas as pd
import os

path = os.path.abspath(__file__).rsplit("/", 1)[0]


def test_fetch_dependency_history():
    test_df = pd.read_csv(path + "/sample_outputs/test_step1.csv")
    result_df = fetch_dependency_history(
        "https://github.com/wasi0013/online-voting-system")
    assert len(result_df) == len(test_df)
    assert len(result_df.columns) == len(test_df.columns)
    assert result_df.author[0] == test_df.author[0]
