# for files in repo/rq_new/*.csv
import csv
import glob
import os
import pandas as pd


class repo_commits:
    def __init__(
        self,
        repo_name,
        commit_sha,
        commit_date,
        package_name,
        package_version,
        max_satisfying_status,
        combined_packages_and_versions,
        final_commit_status,
    ):
        self.repo_name = repo_name
        self.commit_sha = commit_sha
        self.commit_date = commit_date
        self.package_name = package_name
        self.package_version = package_version
        self.max_satisfying_status = max_satisfying_status
        self.combined_packages_and_versions = combined_packages_and_versions
        self.final_commit_status = final_commit_status


class repo_combined_commits:
    def __init__(
        self,
        repo_name,
        commit_sha,
        commit_date,
        affected_packages,
        all_packages,
        affected_count,
        all_count,
        ratio,
        final_commit_status,
        is_fixing,
        is_fixing_reason,
        affected_packages_low,
        affected_packages_low_count,
        affected_packages_medium,
        affected_packages_medium_count,
        affected_packages_high,
        affected_packages_high_count,
    ):
        self.repo_name = repo_name
        self.commit_sha = commit_sha
        self.commit_date = commit_date

        self.affected_packages = affected_packages
        self.all_packages = all_packages
        self.affected_count = affected_count
        self.all_count = all_count
        self.ratio = ratio

        self.final_commit_status = final_commit_status

        self.is_fixing = is_fixing
        self.is_fixing_reason = is_fixing_reason

        self.affected_packages_low = affected_packages_low
        self.affected_packages_low_count = affected_packages_low_count
        self.affected_packages_medium = affected_packages_medium
        self.affected_packages_medium_count = affected_packages_medium_count
        self.affected_packages_high = affected_packages_high
        self.affected_packages_high_count = affected_packages_high_count


class package_name_version:
    def __init__(self, package_name, package_version):
        self.package_name = package_name
        self.package_version = package_version


def repo_commits_combiner(df):
    repo_commits_list = []
    repo_combined_commits_list = []
    repo_unique_sha_list = []
    repo_commits_same_sha_list = []

    for index, row in df.iterrows():
        repo_name = row["repo_name"]
        commit_sha = row["commit_sha"]
        commit_date = row["commit_date"]
        package_name = row["package_name"]
        package_version = row["package_version"]
        max_satisfying_status = row["max_satisfying_status"]
        combined_packages_and_versions = ""
        final_commit_status = ""
        repo_commits_list.append(
            repo_commits(
                repo_name,
                commit_sha,
                commit_date,
                package_name,
                package_version,
                max_satisfying_status,
                combined_packages_and_versions,
                final_commit_status,
            )
        )

    # find unique sha
    for repo_commit in repo_commits_list:
        commit_sha = repo_commit.commit_sha
        if commit_sha not in repo_unique_sha_list:
            repo_unique_sha_list.append(commit_sha)

    # find related commits
    for unique_sha in repo_unique_sha_list:
        repo_commits_same_sha_list = []
        for repo_commit in repo_commits_list:
            if repo_commit.commit_sha == unique_sha:
                repo_commits_same_sha_list.append(repo_commit)

        # commit affected?
        one_affected = False
        one_affected_max_of_low_med_high = ""
        affected_packages_list = []
        affected_packages_low_list = []
        affected_packages_medium_list = []
        affected_packages_high_list = []
        all_packages_list = []
        for repo_commit in repo_commits_same_sha_list:
            all_packages_list.append(
                package_name_version(
                    repo_commit.package_name, repo_commit.package_version
                )
            )
            if repo_commit.max_satisfying_status.strip().startswith("Affected"):
                one_affected = True
                affected_packages_list.append(
                    package_name_version(
                        repo_commit.package_name, repo_commit.package_version
                    )
                )

                if repo_commit.max_satisfying_status.strip().startswith("Affected low"):
                    affected_packages_low_list.append(
                        package_name_version(
                            repo_commit.package_name, repo_commit.package_version
                        )
                    )
                    if one_affected_max_of_low_med_high == "":
                        one_affected_max_of_low_med_high = "low"
                elif repo_commit.max_satisfying_status.strip().startswith(
                    "Affected medium"
                ):
                    affected_packages_medium_list.append(
                        package_name_version(
                            repo_commit.package_name, repo_commit.package_version
                        )
                    )
                    if (one_affected_max_of_low_med_high == "") or (
                        one_affected_max_of_low_med_high == "low"
                    ):
                        one_affected_max_of_low_med_high = "medium"
                elif repo_commit.max_satisfying_status.strip().startswith(
                    "Affected high"
                ):
                    affected_packages_high_list.append(
                        package_name_version(
                            repo_commit.package_name, repo_commit.package_version
                        )
                    )
                    if (
                        (one_affected_max_of_low_med_high == "")
                        or (one_affected_max_of_low_med_high == "low")
                        or (one_affected_max_of_low_med_high == "medium")
                    ):
                        one_affected_max_of_low_med_high = "high"

        commit_affected = ""
        if one_affected:
            commit_affected = "Commit Affected" + " " + one_affected_max_of_low_med_high
        else:
            commit_affected = "Commit Unaffected"
        commit_to_copy = repo_commits_same_sha_list[0]
        division_result = len(affected_packages_list) / len(all_packages_list)
        g = float("{0:.2f}".format(division_result))
        combined_commit = repo_combined_commits(
            commit_to_copy.repo_name,
            commit_to_copy.commit_sha,
            commit_to_copy.commit_date,
            affected_packages_list,
            all_packages_list,
            len(affected_packages_list),
            len(all_packages_list),
            g,
            commit_affected,
            None,
            None,
            affected_packages_low_list,
            len(affected_packages_low_list),
            affected_packages_medium_list,
            len(affected_packages_medium_list),
            affected_packages_high_list,
            len(affected_packages_high_list),
        )
        # repo_name,                commit_sha,                commit_date, affected_packages,      all_packages,      affected_count,              all_count,             ratio,  final_commit_status):
        repo_combined_commits_list.append(combined_commit)

    # extra check
    print(len(repo_unique_sha_list) == len(repo_combined_commits_list))

    repo_combined_commits_list.reverse()
    # mark_fixing_commits(repo_combined_commits_list)
    # write to file
    df = pd.DataFrame(
        columns=[
            "repo_name",
            "commit_sha",
            "commit_date",
            "affected_packages",
            "all_packages",
            "affected_count",
            "all_count",
            "ratio",
            "commit_status",
            "affected_packages_low_list",
            "affected_packages_low_list_count",
            "affected_packages_medium_list",
            "affected_packages_medium_list_count",
            "affected_packages_high_list",
            "affected_packages_high_list_count",
        ]
    )
    data = []
    for repo_commit in repo_combined_commits_list:
        affected_packages_string = ""
        affected_packages_low_string = ""
        affected_packages_medium_string = ""
        affected_packages_high_string = ""
        all_packages_string = ""
        for aff in repo_commit.affected_packages:
            affected_packages_string = (
                affected_packages_string
                + aff.package_name
                + ":"
                + aff.package_version
                + "|"
            )
        affected_packages_string = affected_packages_string[:-1]

        for aff in repo_commit.affected_packages_low:
            affected_packages_low_string = (
                affected_packages_low_string
                + aff.package_name
                + ":"
                + aff.package_version
                + "|"
            )
        affected_packages_low_string = affected_packages_low_string[:-1]

        for aff in repo_commit.affected_packages_medium:
            affected_packages_medium_string = (
                affected_packages_medium_string
                + aff.package_name
                + ":"
                + aff.package_version
                + "|"
            )
        affected_packages_medium_string = affected_packages_medium_string[:-1]

        for aff in repo_commit.affected_packages_high:
            affected_packages_high_string = (
                affected_packages_high_string
                + aff.package_name
                + ":"
                + aff.package_version
                + "|"
            )
        affected_packages_high_string = affected_packages_high_string[:-1]

        for al in repo_commit.all_packages:
            all_packages_string = (
                all_packages_string + al.package_name + ":" + al.package_version + "|"
            )
        all_packages_string = all_packages_string[:-1]

        data.append(
            {
                "repo_name": repo_commit.repo_name,
                "commit_sha": repo_commit.commit_sha,
                "commit_date": repo_commit.commit_date,
                "affected_packages": affected_packages_string,
                "all_packages": all_packages_string,
                "affected_count": repo_commit.affected_count,
                "all_count": repo_commit.all_count,
                "ratio": repo_commit.ratio,
                "commit_status": repo_commit.final_commit_status,
                "affected_packages_low_list": affected_packages_low_string,
                "affected_packages_low_list_count": repo_commit.affected_packages_low_count,
                "affected_packages_medium_list": affected_packages_medium_string,
                "affected_packages_medium_list_count": repo_commit.affected_packages_medium_count,
                "affected_packages_high_list": affected_packages_high_string,
                "affected_packages_high_list_count": repo_commit.affected_packages_high_count,
            }
        )
    df = df.append(data, ignore_index=True)
    return df


# assumes commits are ordered ascending (commit_date)
def mark_fixing_commits(combined_commits_list):
    prev_c = None
    first_loop = True
    for c in combined_commits_list:
        if first_loop:
            prev_c = c
            first_loop = False
            continue

        if (c.affected_count == 0) and (prev_c.affected_count > 0):
            c.is_fixing = True
            affected_packages_string = ""
            for aff in c.affected_packages:
                affected_packages_string = (
                    affected_packages_string
                    + aff.package_name
                    + ":"
                    + aff.package_version
                    + "|"
                )
            affected_packages_string = affected_packages_string[:-1]
            c.is_fixing_reason = affected_packages_string
            prev_c = c
            continue

        c_affected_packages_list = []
        for pckg in c.affected_packages:
            if pckg.package_name.lower().strip() not in c_affected_packages_list:
                c_affected_packages_list.append(pckg.package_name.lower().strip())

        for prev_c_pckg in prev_c.affected_packages:
            if prev_c_pckg.package_name.lower().strip() not in c_affected_packages_list:
                c.is_fixing = True
                c.is_fixing_reason = prev_c_pckg.package_name

        prev_c = c
