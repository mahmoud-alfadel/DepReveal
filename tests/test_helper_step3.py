from dependency_threat.helper.step3 import repo_commits_combiner
import pandas as pd
import os

path = os.path.abspath(__file__).rsplit("/", 1)[0]


def test_repo_commits_combiner():
    input_df = pd.read_csv(path + "/sample_inputs/test_step3.csv")
    result_df = pd.read_csv(path + "/sample_outputs/test_step3.csv")
    test_df = repo_commits_combiner(input_df)
    assert len(test_df) == len(result_df)
