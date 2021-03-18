from dateutil.parser import parse
import pandas as pd
import glob
import os


def date_intervals(start, end, intv):
    """
    finds a list of date time objects between start & end date
    
    :param start: datetime object of starting date
    :param end: datetime object of ending date
    :param intv: interval of the date range
    """
    diff = (end - start) / intv
    for i in range(intv):
        yield start + diff * i
    yield end


def find_commits_at_intervals(df, interval=5):

    percentage = 100 // interval

    df = df[df["commit_date"].str.contains("-")]

    dates = df["commit_date"].apply(parse).tolist()

    df["converted_date"] = df["commit_date"].apply(parse)
    df.set_index(pd.to_datetime(df["converted_date"]), inplace=True)
    min_date = min(dates)
    max_date = max(dates)
    selected_dates = []

    intervals_timestamp_list = []

    for interval_date in date_intervals(min_date, max_date, interval):
        intervals_timestamp_list.append(interval_date)

    first_loop = True
    prev_commit_date = None
    selected_dates.append(min_date)

    for interval_date in intervals_timestamp_list:
        if first_loop:
            # selected_dates.append(min_date)
            prev_commit_date = selected_dates[0]
            first_loop = False
        else:
            for commit_date in dates:
                if commit_date <= interval_date:
                    prev_commit_date = commit_date
                else:
                    break
            selected_dates.append(prev_commit_date)

    # extra check
    if len(selected_dates) != (interval + 1):
        print("ERROR: PROBLEMATIC INPUT")
    data = []
    for item in selected_dates:
        data.extend(df.loc[df["converted_date"] == item].to_dict("records"))
    dd = pd.DataFrame()
    dd = dd.append(data, ignore_index=True)
    dd = dd.drop(["converted_date"], axis=1)
    percentages = [n * percentage for n in range(interval + 1)]

    # special case
    # if "microgateway" in file_name:
    #     dd = dd[ dd['commit_sha'] != 'e48441e2bcdc41f8a84cdaaec16439852ed7f013' ]
    #     dd = dd[ dd['commit_sha'] != '3ac9711004dcfed5b71baeb08341c0965793e4d5' ]

    if len(percentages) == len(dd):
        dd["interval"] = percentages
        dd["interval_boundary_timestamp"] = intervals_timestamp_list
    else:
        print(len(percentages))
        print(len(dd))
        print(dd.head())
        print(percentages)

    # extra check
    if len(dd) != interval + 1:
        print("ERROR: PROBLEMATIC FILE")

    dd = dd[
        [
            "repo_name",
            "commit_date",
            "commit_sha",
            "commit_status",
            "interval",
            "interval_boundary_timestamp",
            "affected_packages_low_list",
            "affected_packages_low_list_count",
            "affected_packages_medium_list",
            "affected_packages_medium_list_count",
            "affected_packages_high_list",
            "affected_packages_high_list_count",
            "all_packages",
            "all_count",
            "affected_packages",
            "affected_count",
            "ratio",
        ]
    ]
    return dd
