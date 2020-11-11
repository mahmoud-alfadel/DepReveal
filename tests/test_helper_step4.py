from dependency_threat.helper.step4 import find_commits_at_intervals
import pandas as pd
import os


path = os.path.abspath(__file__).rsplit("/", 1)[0]


def test_find_commits_at_intervals():
    input_df = pd.read_csv(path + "/sample_inputs/test_step4.csv")
    result_df = pd.read_csv(path + "/sample_outputs/test_step4.csv")
    test_df = find_commits_at_intervals(input_df)
    assert len(test_df) == len(result_df)
    assert len(test_df.columns) == len(result_df.columns)
    assert test_df.repo_name[0] == result_df.repo_name[0]
    assert test_df.commit_sha[0] == result_df.commit_sha[0]
