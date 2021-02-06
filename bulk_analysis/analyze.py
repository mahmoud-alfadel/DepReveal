import pandas as pd
from glob import glob
import os
from datetime import datetime
from pprint import pprint

def median(lst):
    sortedLst = sorted(lst)
    lstLen = len(lst)
    index = (lstLen - 1) // 2
   
    if (lstLen % 2):
        return sortedLst[index]
    else:
        return (sortedLst[index] + sortedLst[index + 1])/2.0

def get_stats(df):
    author, repository = '', ''
    try:
        author, repository = df['repo_name'][0].split("/")
    except:
        pass
    df = df[1:]
    df = df.fillna("")
    df = df.sort_values(['affected_packages_high_list_count', 'affected_packages_medium_list_count', 'affected_packages_low_list_count'], ascending=[False, False, False])
    date_dict = dict()
    
    for _, row in df.iterrows():  
        commit_date = datetime.strptime(datetime.strftime(datetime.strptime(row['commit_date'], "%Y-%m-%d %H:%M:%S+00:00"), "%Y-%m-%d"), "%Y-%m-%d")
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
    
    freq = []
    threat = None
    count = 0
    for index, commit_date in enumerate(sorted(date_dict)):
        if index == 0:   threat, count = date_dict[commit_date], 1         
        elif threat == date_dict[commit_date]: count += 1
        elif threat != date_dict[commit_date]:
            freq.append((threat,count))
            threat, count = date_dict[commit_date], 1
    freq.append((threat,count))
    low_list, medium_list, high_list = [], [], []
    for threat, count in freq:
        if threat == 1: low_list.append(count)
        elif threat == 2: medium_list.append(count)
        elif threat == 3: high_list.append(count)
        
    return {
        "author": author,
        "repository": repository,
        "total_low_days": sum(low_list),
        "total_medium_days": sum(medium_list),
        "total_high_days": sum(high_list),
        "low_period_count": len(low_list),
        "medium_period_count": len(medium_list),
        "high_period_count": len(high_list),
        "avg_low": sum(low_list)/len(low_list),
        "avg_medium": sum(medium_list)/len(medium_list),
        "avg_high": sum(high_list)/len(high_list),
        "min_low": min(low_list),
        "min_medium": min(medium_list),
        "min_high": min(high_list),
        "max_low": max(low_list),
        "max_medium": max(medium_list),
        "max_high": max(high_list),
        "median_low": median(low_list),
        "median_medium": median(medium_list),
         "median_high": median(high_list),

    }

    


def analyze():
    data = []
    for filename in glob(os.path.join("inputs", "*.csv")):
        df = pd.read_csv(filename)
        row = get_stats(df)
        data.append(row)
    master_df = pd.DataFrame()
    master_df = master_df.append(data, ignore_index=True)
    master_df.to_csv("output.csv", index=False)


analyze()