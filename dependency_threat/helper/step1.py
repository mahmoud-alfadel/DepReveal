#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import csv
import sys
import requests
import pandas as pd
import glob
import pytz
import os
import datetime
from datetime import date
pd.options.mode.chained_assignment = None 

def get_package_dependencies(
    sha: str, username: str, repo: str, filename: str = "package.json"
) -> list:
    r = requests.get(
        "https://raw.githubusercontent.com/{}/{}/{}/{}".format(
            username, repo, sha, filename
        )
    )
    try:
        result = r.json()

        dependencies = result.get("dependencies")
        if dependencies:
            return dependencies
    except Exception as e:
        return {}
    return None


def get_commits(
    username: str, repo: str, access_tokens: list = [None], filename: str = "package.json"
) -> list:

    result = []
    for i in range(1, 10000):
        print("commit page: ", i)
        no_next_page = False
        for x, access_token in enumerate(access_tokens, 1):
            access_failed = False
            print("access attempt: ", x)
            if not access_token:
                url = "https://api.github.com/repos/{}/{}/commits?path={}&page={}".format(
                                    username, repo, filename, i) 
            else:  
                url = "https://api.github.com/repos/{}/{}/commits?path={}&page={}&access_token={}".format(
                                    username, repo, filename, i, access_token
                                )
            r = requests.get(url)
            if r.status_code == 403:
                if not access_token: 
                    print("ERROR: Github PUBLIC API REQUEST LIMIT EXHAUSTED.\nYou need an github access token to perform this analysis.")
                    sys.exit(1)
                if x == len(access_tokens):
                    print("Access Token Exausted")
                    sys.exit(1)
                continue
            commits = r.json()
            if commits:
                for commit in commits:
                    try:
                        sha = commit.get("sha")
                        url = commit.get("html_url")
                        commit = commit.get("commit")
                        author, date, message = "", "", ""
                        if commit:
                            author = commit.get("author").get("name")
                            date = commit.get("committer").get("date")
                            message = commit.get("message")
                        else:
                            print(sha, url, "commit not found")
                        if sha:
                            dependencies = get_package_dependencies(sha, username, repo)
                            if dependencies is None:
                                return result
                            if dependencies:
                                for package_name, version in dependencies.items():
                                    result.append(
                                        {
                                            "sha": sha,
                                            "url": url,
                                            "author": author,
                                            "date": date,
                                            "message": message,
                                            "package_name": package_name,
                                            "version": version,
                                        }
                                    )

                    except Exception as e:
                        access_failed = True
                        print(e)
                        break
            else:
                no_next_page = True
                break
            if not access_failed:
                break

        if no_next_page:
            break

    return result


def fetch_dependency_history(github_url: str, access_tokens: list= [None]) -> pd.DataFrame:
    """
       scrapes github repo to extract sha, url, author, date, message, package_name, version
    """
    repo, username = github_url.split("/")[::-1][:2:]
    print("Username:", username)
    print("Repository Name:", repo)
    result = get_commits(username, repo, access_tokens)

    df = pd.DataFrame()
    if result:
        df = df.append(result, ignore_index=True)
        df = df.drop_duplicates()
        df = df[~df["version"].str.contains("/")]
    df['date'] = pd.to_datetime(df['date'])
    today = date.today()
    dates = pd.date_range(df['date'].min().strftime('%Y-%m-%d'), today)
    missing_dates = dates[~dates.isin(df['date'].dt.date)].to_list()    
    avail_dates = dates[dates.isin(df['date'].dt.date)].to_list()[::-1]
    dates = dates.to_list()
    nf = pd.DataFrame()
    for missing_date in missing_dates:
        for last_matched_date in avail_dates:
            if last_matched_date > missing_date: continue
            else: break
        rows = df[df['date'].dt.date == last_matched_date].copy(deep=False)
        rows['date'] = rows['date'].apply(lambda x: pytz.utc.localize(missing_date))
        # print(rows)  print to check the progress
        nf = pd.concat([nf, rows])
    df = pd.concat([df, nf])
    df['date'] = df.date.astype(str)
    # df.to_csv("Continuous_dates.csv", index=False)
    return df
