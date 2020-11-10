from semver import max_satisfying as semver_max_satisfying
import os
import glob
import csv
from time import sleep
import tqdm
import pandas as pd

base_path = os.path.abspath(__file__).rsplit("/", 1)[0]


class npm_advisory:
    def __init__(
        self,
        id,
        created,
        updated,
        deleted,
        title,
        module_name,
        vulnerable_versions,
        patched_versions,
        access,
        severity,
        cwe,
        url,
        recommendation,
        published,
        reported,
        status,
        version,
    ):
        self.id = id
        self.created = created
        self.updated = updated
        self.deleted = deleted
        self.title = title
        self.module_name = module_name
        self.vulnerable_versions = vulnerable_versions
        self.patched_versions = patched_versions
        self.access = access
        self.severity = severity
        self.cwe = cwe
        self.url = url
        self.recommendation = recommendation
        self.published = published
        self.reported = reported
        self.status = status  # Affected/Unaffected
        self.version = version  # exact version number


npm_advisory_list = []
npm_advisory_map = {}


def load_advisories(all_advisories_v3_file_path, NPM_Advisories_list):
    """
        Loads the NPM advisory into a global variable npm_advisory_list and npm_advisory_map (for multiple vulnerailities)
    """
    print("entering load_advisories")
    with open(all_advisories_v3_file_path, "r", encoding="mac_roman") as f:
        reader = csv.DictReader(f, delimiter=",")
        for row in reader:
            advisory_id = row["id"]
            created = row["created"]
            updated = row["updated"]
            deleted = row["deleted"]
            title = row["title"]
            module_name = row["module_name"].lower().strip()
            vulnerable_versions = row["vulnerable_versions"]
            patched_versions = row["patched_versions"]
            access = row["access"]
            severity = row["severity"]
            cwe = row["cwe"]
            url = row["url"]
            recommendation = row["recommendation"]
            published = row["published"]
            reported = row["reported"]
            status = row["status"]  # Affected/Unaffected
            version = row["version"]  # exact version number

            advisory_obj = npm_advisory(
                advisory_id,
                created,
                updated,
                deleted,
                title,
                module_name,
                vulnerable_versions,
                patched_versions,
                access,
                severity,
                cwe,
                url,
                recommendation,
                published,
                reported,
                status,
                version,
            )
            # Keep the list for now
            npm_advisory_list.append(advisory_obj)

            # Check if package is in module
            if module_name in npm_advisory_map:
                versions_dict = npm_advisory_map[module_name]
            else:
                versions_dict = {}
                npm_advisory_map[module_name] = versions_dict

            if version not in versions_dict:
                # For now, only add if the version is not in versions_dict
                # to emulate the behavior of the list search
                # FIXME: Make ths into a list of advisory objects to iterate - multiple vulnerabilities in a single version
                list_vulnerability = []
                npm_advisory_map[module_name][version] = list_vulnerability
                npm_advisory_map[module_name][version].append(advisory_obj)
            else:
                npm_advisory_map[module_name][version].append(advisory_obj)

    print(len(npm_advisory_list))
    print("leaving load_advisories")


###################################


class Package_Version_Time:
    def __init__(self, package, version, time):
        self.package = package
        self.version = version
        self.time = time


Package_Version_Time_list = []
Package_Version_Time_map = {}


def load_npm_packages_versions_releasetime(
    packages_versions_time_file_path, Package_Version_Time_list
):
    print("entering load_npm_packages_versions_releasetime")
    with open(packages_versions_time_file_path, "r", encoding="mac_roman") as f:
        reader = csv.DictReader(f, delimiter=",")
        for row in reader:
            package = row["package"]
            version = row["version"]
            time = row["time"]
            if version == "created":
                continue

            pkg_version = Package_Version_Time(package, version, time)
            Package_Version_Time_list.append(pkg_version)

            # There is an entry in the map
            if package in Package_Version_Time_map:
                # Get versions list
                versions_list = Package_Version_Time_map[package]
            # There is no entry in the map yet, so create it
            else:
                versions_list = []
                Package_Version_Time_map[package] = versions_list

            # Append it to the list
            versions_list.append(pkg_version)

    # print(len(Package_Version_Time_list))
    print("leaving load_npm_packages_versions_releasetime")


###################################


class Repo_Commit:
    def __init__(
        self,
        repo_name,
        commit_sha,
        commit_date,
        package_name,
        package_version,
        max_satisfying_version,
        max_satisfying_version_release_time,
        max_satisfying_status,
        max_satisfying_published,
        vulnerability_url,
    ):
        self.repo_name = repo_name
        self.commit_sha = commit_sha
        self.commit_date = commit_date
        self.package_name = package_name
        self.package_version = package_version
        self.max_satisfying_version = max_satisfying_version  # version number
        self.max_satisfying_version_release_time = max_satisfying_version_release_time
        self.max_satisfying_status = max_satisfying_status  # affected/unaffected
        self.max_satisfying_published = max_satisfying_published  # disclosed
        self.vulnerability_url = vulnerability_url  # vulnerability_url


def load_repo_file(df, NPM_Advisories, Package_Version_Time):
    print("entering load_repo_file")
    Repo_Commit_list = []
    # load repo file into Repo_Commit_list
    repo_name = "X"
    repo_name_is_set = False
    for index, row in df.iterrows():
        commit_sha = row["sha"]
        commit_date = row["date"]
        package_name = row["package_name"]
        package_version = row["version"]  # semver
        if repo_name_is_set == False:
            url = row["url"]
            repo_name = url[len("https://github.com/") :]
            index_of_first_slash = repo_name.find("/")
            index_of_second_slash = repo_name.find("/", index_of_first_slash + 1)
            repo_name = repo_name[:index_of_second_slash]
            repo_name_is_set = True
        # Add to another global list
        Repo_Commit_list.append(
            Repo_Commit(
                repo_name,
                commit_sha,
                commit_date,
                package_name,
                package_version,
                None,
                None,
                None,
                None,
                None,
            )
        )

    # collect the versions of the packages, release before the commit_date
    # send them with the semver to get the max satisfying
    # find the max satisfying in the advisories

    for repo_commit in tqdm.tqdm(Repo_Commit_list):
        package_name = repo_commit.package_name
        package_semver = repo_commit.package_version

        def find_package_versions(package_name):
            package_versions_list = []
            # Search for the package name in the dataset we load in step 2 (Package_Version_Time_list)
            if package_name in Package_Version_Time:
                versions_list = Package_Version_Time[package_name]

                # Find the versions released before the commit.commit_date
                for version in versions_list:
                    if version.time <= repo_commit.commit_date:
                        package_versions_list.append(version.version)

            return package_versions_list

        package_versions_list = find_package_versions(package_name)
        # print(package_name)
        # print(package_semver)
        # print(",".join(package_versions_list))
        # At this point, package_versions_list contains all versions of the package the application depends

        if len(package_versions_list) == 0:
            repo_commit.max_satisfying_status = (
                "Package not in advisories"  # was: Package name not found
            )
        else:

            # Calls an external process to resolve the semver
            _max_satisfying_version = semver_max_satisfying(
                package_versions_list,
                package_semver,
                include_prerelease=True,
                loose=True,
            )

            def classify_package_vulnerability_status(_max_satisfying_version):

                # now check if it's vulnerable(affected)
                npm_advisory_for_the_package = None
                found = False
                foundType = ""  # low, medium, high
                emptyPublished = 0
                emptyReported = 0
                Special_Case = False

                formatted_package_name = package_name.lower().strip()

                # If the package name is in the advisories
                if formatted_package_name in NPM_Advisories:
                    # get all the versions of the vulnerable packages in the npm advisories map
                    versions_map = NPM_Advisories[formatted_package_name]
                    # FIXME: Update the code to consider multiple vulnerabilities in a single version

                    # If version is in the advisor
                    if _max_satisfying_version in versions_map:

                        # loop from the vulnerabilities for _max_satisfying_version of the formatted_package_name
                        for npm_advisory in versions_map[_max_satisfying_version]:

                            # In the advisories we have only 2 states: "Unaffected" or "Affected"
                            # We need to classify the level of exploitability based on the date of the commit
                            if npm_advisory.status == "Unaffected":
                                if foundType not in ["low", "medium", "high"]:
                                    npm_advisory_for_the_package = npm_advisory

                            # Now, it is affected:
                            elif (
                                npm_advisory.published.strip() != ""
                                and npm_advisory.reported.strip() != ""
                            ):  # general case: data exists
                                if repo_commit.commit_date > npm_advisory.published:
                                    foundType = "high"
                                    npm_advisory_for_the_package = npm_advisory
                                    break

                                elif (
                                    repo_commit.commit_date < npm_advisory.published
                                    and repo_commit.commit_date > npm_advisory.reported
                                ):
                                    foundType = "medium"
                                    npm_advisory_for_the_package = npm_advisory

                                elif repo_commit.commit_date < npm_advisory.reported:
                                    if foundType != "medium":
                                        foundType = "low"
                                        npm_advisory_for_the_package = npm_advisory

                                else:
                                    if foundType not in ["low", "medium", "high"]:
                                        foundType = (
                                            "commit date equal to reported or published"
                                        )
                                        Special_Case = True
                                        npm_advisory_for_the_package = npm_advisory

                            # In case we do not have data about reported_date or published_date
                            # In these cases we assign the created and updated date to reported and published
                            elif (
                                npm_advisory.published.strip() == ""
                                or npm_advisory.reported.strip() == ""
                            ):  # reported: created, published: updated
                                npm_advisory_reported = None
                                npm_advisory_published = None
                                if npm_advisory.reported.strip() == "":
                                    npm_advisory_reported = npm_advisory.created
                                if npm_advisory.published.strip() == "":
                                    npm_advisory_published = npm_advisory.updated

                                if repo_commit.commit_date > npm_advisory_published:
                                    foundType = "high (empty reported or published)"
                                    npm_advisory_for_the_package = npm_advisory
                                    break

                                elif (
                                    repo_commit.commit_date < npm_advisory_published
                                    and repo_commit.commit_date > npm_advisory_reported
                                ):
                                    foundType = "medium (empty reported or published)"
                                    npm_advisory_for_the_package = npm_advisory

                                elif repo_commit.commit_date < npm_advisory_reported:
                                    if foundType != "medium":
                                        foundType = "low (empty reported or published)"
                                        npm_advisory_for_the_package = npm_advisory

                                else:
                                    if foundType not in ["low", "medium", "high"]:
                                        foundType = "commit date equal to reported or published (empty reported or published)"
                                        Special_Case = True
                                        npm_advisory_for_the_package = npm_advisory

                        # UPDATE REPO_COMMIT
                        repo_commit.max_satisfying_version = (
                            npm_advisory_for_the_package.version
                        )
                        repo_commit.max_satisfying_status = (
                            npm_advisory_for_the_package.status + " " + foundType
                        )  # affected/unaffected
                        # add more info about the vulnerability in the REPO_COMMIT
                        repo_commit.vulnerability_url = (
                            npm_advisory_for_the_package.url
                        )  # vulnerability_url

                    else:
                        # The package might be too new for NPM to keep track of it
                        # In these cases we assign Version not in advisories
                        repo_commit.max_satisfying_version = _max_satisfying_version
                        repo_commit.max_satisfying_status = "Version not in advisories"
                        # if (Special_Case):
                        #     repo_commit.max_satisfying_status = "Advisory reported or published at the commit date"

            classify_package_vulnerability_status(_max_satisfying_version)

    # now each repo commit is loaded with the additional data, you can save it to new file
    df = pd.DataFrame(
        columns=[
            "repo_name",
            "commit_sha",
            "commit_date",
            "package_name",
            "package_version",
            "max_satisfying_version",
            "max_satisfying_status",
            "vulnerability_url",
        ]
    )
    data = []
    for repo_commit in Repo_Commit_list:
        data.append(
            {
                "repo_name": repo_commit.repo_name,
                "commit_sha": repo_commit.commit_sha,
                "commit_date": repo_commit.commit_date,
                "package_name": repo_commit.package_name,
                "package_version": repo_commit.package_version,
                "max_satisfying_version": repo_commit.max_satisfying_version,
                "max_satisfying_status": repo_commit.max_satisfying_status,
                "vulnerability_url": repo_commit.vulnerability_url,
            }
        )
    df = df.append(data, ignore_index=True)
    return df


def identifying_vulnerability_levels(df):
    ################################### load the scripts in order ###################################
    # 1. load advisories
    all_advisories_v3_filePath = os.path.join(base_path, "data", "npm_advisories.csv")
    load_advisories(all_advisories_v3_filePath, NPM_Advisories_list=npm_advisory_list)

    # 2. load package_version_time
    package_version_time_filePath = os.path.join(
        base_path, "data", "package_version_time.csv"
    )
    load_npm_packages_versions_releasetime(
        package_version_time_filePath,
        Package_Version_Time_list=Package_Version_Time_list,
    )
    return load_repo_file(
        df,
        NPM_Advisories=npm_advisory_map,
        Package_Version_Time=Package_Version_Time_map,
    )
