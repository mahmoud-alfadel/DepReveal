from dependency_threat.helper.step2 import identifying_vulnerability_levels
import pandas as pd
import os

path = os.path.abspath(__file__).rsplit("/", 1)[0]


def test_identifying_vulnerability_levels():
    input_df = pd.read_csv(path + "/sample_inputs/test_step2.csv")
    result_df = pd.read_csv(path + "/sample_outputs/test_step2.csv")
    test_df = identifying_vulnerability_levels(input_df)
    assert len(test_df) == len(result_df)
