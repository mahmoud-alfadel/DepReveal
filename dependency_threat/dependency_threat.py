from dependency_threat.helper.step1 import fetch_dependency_history
from dependency_threat.helper.step2 import identifying_vulnerability_levels
from dependency_threat.helper.step3 import repo_commits_combiner
from dependency_threat.helper.step4 import find_commits_at_intervals
from jinja2 import Template
import os
path = os.path.abspath(__file__).rsplit("/", 1)[0]
from colorama import init, Fore, Back, Style
import pandas as pd
from collections import Counter
from datetime import datetime
from pprint import pprint
from dateutil import parser

def analyze(github_url, access_tokens, interval=5):
    print(f"{Fore.GREEN}Running Step 1: fetching dependency history{Style.RESET_ALL}")
    df = fetch_dependency_history(github_url, access_tokens)

    print(f"{Fore.GREEN}Running Step 2: identifying vulnerability levels{Style.RESET_ALL}")
    df = identifying_vulnerability_levels(df)
    df = df.drop_duplicates(subset=['commit_date', 'package_name'])
    
    print(f"{Fore.GREEN}Running Step 3: combining repo commits{Style.RESET_ALL}")
    result_df = repo_commits_combiner(df)
    
    print("Done.")
    # result_df = pd.read_csv(os.path.join(path,'helper', 'data', 'dummy_output.csv'))
    return result_df

def generate_html(df):
    try:
        author, repository = df['repo_name'][0].split("/")
    except:
        pass
    data = []
    #in case we want to remove the 0% in the html page
    df = df[1:]
    df = df.fillna("")
    df = df.sort_values(['affected_packages_high_list_count', 'affected_packages_medium_list_count', 'affected_packages_low_list_count'], ascending=[False, False, False])
    #print(df)
    intervals = []
    low_threats= []
    medium_threats= []
    high_threats=[]
    unaffected= []

    high_timeline_date, low_timeline_date, medium_timeline_date, unaffected_timeline_date = [], [], [], []
    temp = set()
    date_dict = dict()
    low_list, medium_list, high_list = [], [], []
    for ind, row in df.iterrows():
        # print(row['affected_count'])
        
        commit_date = datetime.strftime(datetime.strptime(row['commit_date'], "%Y-%m-%d %H:%M:%S+00:00"), "%Y-%m-%d")
        if commit_date not in intervals:
            intervals.append(commit_date)
            low_threats.append(row['affected_packages_low_list_count'])
            medium_threats.append(row['affected_packages_medium_list_count'])
            high_threats.append(row['affected_packages_high_list_count'])
            unaffected.append(row['all_count'] - row['affected_count'])

        high_threat_count = row.get('affected_packages_high_list_count', 0)
        medium_threat_count = row.get('affected_packages_medium_list_count', 0)
        low_threat_count = row.get("affected_packages_low_list_count", 0)
        if not date_dict.get(commit_date):  date_dict[commit_date] = 0

        if high_threat_count != 0:
                    date_dict[commit_date] = 3
        if medium_threat_count != 0:
                date_dict[commit_date] = max([date_dict.get(commit_date, 0), 2])
        if low_threat_count != 0:
                date_dict[commit_date] = max([date_dict.get(commit_date, 0), 1])
        if high_threat_count == 0 and low_threat_count == 0 and medium_threat_count == 0:
                date_dict[commit_date] = max([date_dict.get(commit_date, 0), 0])
        index = ind - 1
        data.append(row.to_dict())
        if row['affected_packages_low_list']: low_list.extend(row['affected_packages_low_list'].split("|"))
        if row['affected_packages_medium_list']: medium_list.extend(row['affected_packages_medium_list'].split("|"))
        if row['affected_packages_high_list']: high_list.extend(row['affected_packages_high_list'].split("|"))
    
    high_timeline_date = [ key for key, value in date_dict.items() if value == 3]
    medium_timeline_date = [ key for key, value in date_dict.items() if value == 2]
    low_timeline_date = [ key for key, value in date_dict.items() if value == 1]
    unaffected_timeline_date = [ key for key, value in date_dict.items() if value == 0]
    new_dict = dict()
    for key, value in date_dict.items():
        new_dict[datetime.strptime(key, "%Y-%m-%d").timestamp()] = value
    # pprint(new_dict)
    # pprint(intervals )
    with open(os.path.join(path,"helper", "data", "template.html"), 'r') as f:
        template = Template(f.read())
        return template.render(
            data=data,
            author=author, 
            repository=repository, 
            intervals=intervals, 
            low_threats= low_threats,
            medium_threats= medium_threats,
            high_threats = high_threats,
            unaffected= unaffected,
            high_timeline_date=high_timeline_date,
            high_timeline=[0]*len(high_timeline_date),
            medium_timeline_date=medium_timeline_date,
            medium_timeline=[0]*len(medium_timeline_date),
            low_timeline_date=low_timeline_date,
            low_timeline=[0]*len(low_timeline_date),
            unaffected_timeline_date=unaffected_timeline_date,
            unaffected_timeline=[0]*len(unaffected_timeline_date),
            low_list=dict(Counter(low_list)),
            medium_list= dict(Counter(medium_list)),
            high_list = dict(Counter(high_list)),
            date_dict = dict(new_dict),
            max_date = max(new_dict.keys())*1000   
            )

