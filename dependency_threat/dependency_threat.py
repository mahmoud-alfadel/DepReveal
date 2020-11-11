from dependency_threat.helper.step1 import fetch_dependency_history
from dependency_threat.helper.step2 import identifying_vulnerability_levels
from dependency_threat.helper.step3 import repo_commits_combiner
from dependency_threat.helper.step4 import find_commits_at_intervals
from jinja2 import Template
import os
path = os.path.abspath(__file__).rsplit("/", 1)[0]


def analyze(github_url, access_tokens, interval=5):
    print("Running Step 1: fetching dependency history")
    df = fetch_dependency_history(github_url, access_tokens)
    print("Running Step 2: identifying vulnerability levels")
    df = identifying_vulnerability_levels(df)
    print("Running Step 3: combining repo commits")
    df = repo_commits_combiner(df)
    print("Running Step 4: Finding commits at intervals")
    result_df = find_commits_at_intervals(df, interval)
    print("Done.")
    return result_df
def generate_html(df):
    try:
        author, repository = df['repo_name'][0].split("/")
    except:
        pass
    data = []
    #in case we want to remove the 0%
    #df = df[~df['interval'].str.contains('20')]
    for index, row in df.iterrows():
        data.append(row.to_dict())
    with open(os.path.join(path,"helper", "data", "template.html"), 'r') as f:
        template = Template(f.read())
        return template.render(
            data=data,
            author=author, 
            repository=repository, 
            intervals=list(df['interval']), 
            low_threats=list(df['affected_packages_low_list_count']),
            medium_threats=list(df['affected_packages_medium_list_count']),
            high_threats=list(df['affected_packages_high_list_count']),
            unaffected=list( x-y for x,y in zip(df['all_count'] , df['affected_count']))
            )

