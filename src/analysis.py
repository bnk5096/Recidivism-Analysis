import os
import csv
import json
import statistics
from dateutil import parser
from scipy.stats import spearmanr, mannwhitneyu

def build_dict_init(path):
    results = {}
    for file in os.listdir(path):
        if file.endswith(".json"):
            filepath = os.path.join(path, file)
            with open(filepath, 'r') as f:
                data = json.load(f)
                results[file[:-5]] = data
    return results


def prev_stats_overall(data):
    resulting_percents = {}
    projects = 0
    total_vuln = 0
    eligibile = 0
    recid = 0
    type_recid = 0
    mod_recid = 0
    oaf_type = 0
    faf_type = 0
    oaf_mod = 0
    faf_mod = 0
    only_tr = 0
    only_mr = 0
    both = 0
    for project in data:
        if len(data[project]) < 2:
            continue
        projects += 1
        # Stats for a project
        vuln = 0
        r = 0
        tr = 0
        mr = 0
        oaf_tr = 0
        faf_tr = 0
        oaf_mr = 0
        faf_mr = 0
        o_tr = 0
        o_mr = 0
        b = 0
        for cve in data[project]:
            # Stats for a single CVE
            vuln += 1
            if cve["intro_duplicate_type"]:
                oaf_tr += 1
            if cve["fix_duplicate_type"]:
                faf_tr += 1
            if cve["intro_duplicate_type"] or cve["fix_duplicate_type"]:
                tr += 1

            if cve["file_fixed_before_fixed_again"]:
                faf_mr += 1
            if cve["file_fixed_before_vuln_again"]:
                oaf_mr += 1
            if cve["file_fixed_before_fixed_again"] or cve["file_fixed_before_vuln_again"]:
                mr += 1

            if cve["intro_duplicate_type"] or cve["fix_duplicate_type"] or cve["file_fixed_before_fixed_again"] or cve["file_fixed_before_vuln_again"]:
                r += 1

            if (cve["intro_duplicate_type"] or cve["fix_duplicate_type"]) and not cve["file_fixed_before_fixed_again"] and not cve["file_fixed_before_vuln_again"]:
                o_tr += 1
            elif (cve["file_fixed_before_fixed_again"] or cve["file_fixed_before_vuln_again"]) and not cve["intro_duplicate_type"] and not cve["fix_duplicate_type"]:
                o_mr += 1
            elif (cve["intro_duplicate_type"] or cve["fix_duplicate_type"]) and (cve["file_fixed_before_fixed_again"] or cve["file_fixed_before_vuln_again"]):
                b += 1
            
  
        elig = vuln - 1
        resulting_percents[project] = {}
        # Total Vulnerabilities 
        resulting_percents[project]["total_vuln"] = vuln
        resulting_percents[project]["eligible"] = elig
        # Recidivism in General
        resulting_percents[project]["recidivistic"] = r
        resulting_percents[project]["recid_percent_tot"] = r/vuln
        resulting_percents[project]["recid_percent_elig"] = r/elig
        # Type Recidivism
        resulting_percents[project]["type_recidivistic"] = tr
        resulting_percents[project]["type_percent_tot"] = tr/vuln
        resulting_percents[project]["type_percent_elig"] = tr/elig
        # FAF
        resulting_percents[project]["type_faf"] = faf_tr
        resulting_percents[project]["type_faf_percent_tot"] = faf_tr/vuln
        resulting_percents[project]["type_faf_percent_elig"] = faf_tr/elig
        # OAF
        resulting_percents[project]["type_oaf"] = oaf_tr
        resulting_percents[project]["type_oaf_percent_tot"] = oaf_tr/vuln
        resulting_percents[project]["type_oaf_percent_elig"] = oaf_tr/elig
        # Mod Recidivism
        resulting_percents[project]["mod_recidivistic"] = mr
        resulting_percents[project]["mod_percent_tot"] = mr/vuln
        resulting_percents[project]["mod_percent_elig"] = mr/elig
        # FAF
        resulting_percents[project]["mod_faf"] = faf_mr
        resulting_percents[project]["mod_faf_percent_tot"] = faf_mr/vuln
        resulting_percents[project]["mod_faf_percent_elig"] = faf_mr/elig
        # OAF
        resulting_percents[project]["mod_oaf"] = oaf_mr
        resulting_percents[project]["mod_oaf_percent_tot"] = oaf_mr/vuln
        resulting_percents[project]["mod_oaf_percent_elig"] = oaf_mr/elig
        # Type Only
        resulting_percents[project]["type_only"] = o_tr
        resulting_percents[project]["percent_type_only"] = o_tr/elig
        # Mod Only
        resulting_percents[project]["mod_only"] = o_mr
        resulting_percents[project]["percent_mod_only"] = o_mr/elig
        # Both
        resulting_percents[project]["both"] = b
        resulting_percents[project]["percent_both"] = b/elig
        # Add to new results dictionary for project_by_project analysis

        # Combine with full results
        total_vuln += vuln
        eligibile += elig
        recid += r
        type_recid += tr
        mod_recid += mr
        oaf_type += oaf_tr
        faf_type += faf_tr
        oaf_mod += oaf_mr
        faf_mod += faf_mr
        only_tr += o_tr
        only_mr += o_mr
        both += b

    print("Overall Stats:")
    print("Projects:", projects)
    print("Total Vuln:", total_vuln)
    print("Eligible:", eligibile)
    print("Recidivistic:", recid)
    print("Type Recidivistic:", type_recid)
    print("\tOAF Type:", oaf_type)
    print("\tFAF Type", faf_type)
    print("Only Type:", only_tr)
    print("Mod Recidivistic:", mod_recid)
    print("\tOAF Mod:", oaf_mod)
    print("\tFAF Mod:", faf_mod)
    print("Only Mod:", only_mr)
    print("Both:", both)


    values = [project["recid_percent_elig"] for project in resulting_percents.values()]
    values.sort()
    print("Median Recidivism Percentage of Eligible:", statistics.median(values))

    projects_at_50 = [project for project, info in resulting_percents.items() if info["recid_percent_elig"] >= 0.5]
    print("Projects at 50% or more", len(projects_at_50))
    print("Percent of Projects at 50% or more", len(projects_at_50)/projects)
    
    projects_at_75 = [project for project, info in resulting_percents.items() if info["recid_percent_elig"] >= 0.75]
    print("Projects at 75% or more", len(projects_at_75))
    print("Percent of Projects at 75% or more", len(projects_at_75)/projects)

    projects_at_100 = [project for project, info in resulting_percents.items() if info["recid_percent_elig"] == 1]
    print("Projects at 100%", len(projects_at_100))
    print("Percent of Projects at 100%", len(projects_at_100)/projects)  

    projects_at_0 = [project for project, info in resulting_percents.items() if info["recid_percent_elig"] == 0]
    print("Projects at 0%", len(projects_at_0))
    print("Percent of Projects at 0%", len(projects_at_0)/projects)  

    return resulting_percents

def get_newest_complex(complexity_map):
    dates = []
    for key in complexity_map:
        dates.append(parser.parse(key))
    newest = str(max(dates)).split(" ")[0]
    return complexity_map[newest]

def complexity(percent_data, core_data):
    # Build dictionary of Project -> Snapshot Date -> Normalized Complexity
    results = {}
    for directory in percent_data:
        results[directory] = {}
        for file in os.listdir(f"complexities/{directory}"):
            if file.endswith(".csv"):
                filepath = os.path.join(f"complexities/{directory}", file)
                complexity_sum = 0
                code_sum = 0
                with open(filepath, newline='') as csvfile:
                    reader = csv.DictReader(csvfile)
                    for row in reader:
                        complexity_sum += int(row['Complexity'])
                        code_sum += int(row['Code'])
                normalized = complexity_sum / code_sum if code_sum else 0
                results[directory][filepath[-14:-4]] = normalized
    complexities = []
    percent_overall = []
    percent_type = []
    percent_mod = []
    to_delete = []
    for project in results:
        try:
            print(project)
            complexities.append(get_newest_complex(results[project]))
            percent_overall.append(percent_data[project]["recid_percent_elig"])
            percent_type.append(percent_data[project]["type_percent_elig"])
            percent_mod.append(percent_data[project]["mod_percent_elig"])
            print("Finished Complexity", project)
        except:
            print("FAILED TO GET COMPLEXITY DATA FOR", project)
            to_delete.append(project)
    
    for d in to_delete:
        del results[d]

    corr, p_value = spearmanr(complexities, percent_overall)
    print(f"\nSpearman correlation Overall: {corr:.3f}, p-value: {p_value:.3g}")

    corr, p_value = spearmanr(complexities, percent_type)
    print(f"Spearman correlation Type: {corr:.3f}, p-value: {p_value:.3g}")

    corr, p_value = spearmanr(complexities, percent_mod)
    print(f"Spearman correlation Mod: {corr:.3f}, p-value: {p_value:.3g}")

    # Get snapshots
    snapshot_dict = {}
    for project in results:
        snapshot_dict[project] = {}
        load_file = "intervals/" + project + ".csv"
        with open(load_file, newline='', encoding='utf-8') as csvfile:
            reader = csv.reader(csvfile)
            next(reader)
            for row in reader:
                if row[0].split(" ")[0] not in results[project]:
                    continue
                snapshot_dict[project][row[0]] = {
                    "fixed_vulns": 0,
                    "recid_vulns": 0,
                    "recid_type": 0,
                    "recid_mod": 0,
                    "recid_both": 0,
                    "delta_comp": None
                } 

        # Put the snapshots in order
        key_dates = []
        for key in snapshot_dict[project]:
            key_dates.append(parser.parse(key))
        key_dates.sort()

        # Get the CVEs put in
        for cve in core_data[project]:
            recid = cve["fix_duplicate_type"] or cve["intro_duplicate_type"] or cve["file_fixed_before_fixed_again"] or cve["file_fixed_before_vuln_again"]
            recid_type = cve["fix_duplicate_type"] or cve["intro_duplicate_type"]
            recid_mod = cve["file_fixed_before_fixed_again"] or cve["file_fixed_before_vuln_again"]
            recid_both = recid_type and recid_mod

            target_date = parser.parse(cve["earliest_patch_date"])
            for date in key_dates:
                if target_date < date:
                    snapshot_dict[project][str(date)]["fixed_vulns"] += 1
                    if recid:
                        snapshot_dict[project][str(date)]["recid_vulns"] += 1
                        if recid_type:
                            snapshot_dict[project][str(date)]["recid_type"] += 1
                        if recid_mod:
                            snapshot_dict[project][str(date)]["recid_mod"] += 1
                        if recid_both:
                            snapshot_dict[project][str(date)]["recid_both"] += 1
                    break
        # Put in the complexity data
        for i in range(len(key_dates)):
            lookup = str(key_dates[i]).split(" ")[0]
            # print(project)
            # print(results[project])
            base = results[project][lookup]
            if i == 0:
                snapshot_dict[project][str(key_dates[i])]["delta_comp"] = base
            else:
                lookup_old = str(key_dates[i-1]).split(" ")[0]
                base_old = results[project][lookup_old]
                snapshot_dict[project][str(key_dates[i])]["delta_comp"] = base - base_old
        
    # Calculate some results
    pos_delta_type = []
    pos_delta_mod = []
    pos_delta_none = 0

    zero_delta_type = []
    zero_delta_mod = []
    zero_delta_none = 0

    neg_delta_type = []
    neg_delta_mod = []
    neg_delta_none = 0

    for project in snapshot_dict:
        for snapshot in snapshot_dict[project]:
            if snapshot_dict[project][snapshot]["delta_comp"] > 0:
                if snapshot_dict[project][snapshot]["fixed_vulns"] == 0 or snapshot_dict[project][snapshot]["recid_vulns"] == 0:
                    pos_delta_none += 1
                else:
                    pos_delta_type.append(snapshot_dict[project][snapshot]["recid_type"]/snapshot_dict[project][snapshot]["fixed_vulns"])
                    pos_delta_mod.append(snapshot_dict[project][snapshot]["recid_mod"]/snapshot_dict[project][snapshot]["fixed_vulns"])
            elif snapshot_dict[project][snapshot]["delta_comp"] == 0:
                if snapshot_dict[project][snapshot]["fixed_vulns"] == 0:
                    zero_delta_none += 1
                else:
                    zero_delta_type.append(snapshot_dict[project][snapshot]["recid_type"]/snapshot_dict[project][snapshot]["fixed_vulns"])
                    zero_delta_mod.append(snapshot_dict[project][snapshot]["recid_mod"]/snapshot_dict[project][snapshot]["fixed_vulns"])
            else:
                if snapshot_dict[project][snapshot]["fixed_vulns"] == 0:
                    neg_delta_none += 1
                else:
                    neg_delta_type.append(snapshot_dict[project][snapshot]["recid_type"]/snapshot_dict[project][snapshot]["fixed_vulns"])
                    neg_delta_mod.append(snapshot_dict[project][snapshot]["recid_mod"]/snapshot_dict[project][snapshot]["fixed_vulns"])

    print("\n--Positive Complexity Delta--")
    print("Total Positive Periods:", len(pos_delta_type) + len(pos_delta_mod) + pos_delta_none)
    print("Positive Periods with 0 Recidivism:", pos_delta_none)
    print("Positive Periods with Type Recidivism", len(pos_delta_type))
    try:
        print("Median Type Recid Rate Among Recidivistic Periods:", statistics.median(pos_delta_type))
        print("Mean Type Recid Rate Among Recidivistic Periods:", statistics.mean(pos_delta_type))
    except:
        pass
    print("Positive Periods with Module Recidivism", len(pos_delta_mod))
    try:
        print("Median Module Recid Rate Among Recidivistic Periods:", statistics.median(pos_delta_mod))
        print("Mean Module Recid Rate Among Recidivistic Periods:", statistics.mean(pos_delta_mod))
    except:
        pass
    print()

    print("--Stable/Zero Complexity Delta--")
    print("Total Zero Periods:", len(zero_delta_type) + len(zero_delta_mod) + zero_delta_none)
    print("Zero Periods with 0 Recidivism:", zero_delta_none)
    print("Zero Periods with Type Recidivism", len(zero_delta_type))
    try:
        print("Median Type Recid Rate Among Recidivistic Periods:", statistics.median(zero_delta_type))
        print("Mean Type Recid Rate Among Recidivistic Periods:", statistics.mean(zero_delta_type))
    except:
        pass
    print("Zero Periods with Module Recidivism", len(zero_delta_mod))
    try:
        print("Median Module Recid Rate Among Recidivistic Periods:", statistics.median(zero_delta_mod))
        print("Mean Module Recid Rate Among Recidivistic Periods:", statistics.mean(zero_delta_mod))
    except:
        pass
    print()

    print("--Negative Complexity Delta--")
    print("Total Negative Periods:", len(neg_delta_type) + len(neg_delta_mod) + neg_delta_none)
    print("Negative Periods with 0 Recidivism:", neg_delta_none)
    print("Negative Periods with Type Recidivism", len(neg_delta_type))
    try:
        print("Median Type Recid Rate Among Recidivistic Periods:", statistics.median(neg_delta_type))
        print("Mean Type Recid Rate Among Recidivistic Periods:", statistics.mean(neg_delta_type))
    except:
        pass
    print("Negative Periods with Module Recidivism", len(neg_delta_mod))
    try:
        print("Median Module Recid Rate Among Recidivistic Periods:", statistics.median(neg_delta_mod))
        print("Mean Module Recid Rate Among Recidivistic Periods:", statistics.mean(neg_delta_mod))
    except:
        pass
    print()

def changes_and_authorship(core_data, percent_data):
    data_manager = {}
    # Load up the snapshots
    for project in percent_data:
        churn_data = None
        data_manager[project] = {}
        load_file = "intervals/" + project + ".csv"
        with open(load_file, newline='', encoding='utf-8') as csvfile:
            reader = csv.reader(csvfile)
            next(reader)
            for row in reader:
                # if row[0].split(" ")[0] not in results[project]:
                #     continue
                data_manager[project][row[0]] = {
                    "total_add": 0,
                    "total_del": 0,
                    "total_change": 0,
                    "authors": set(),
                    "commits": 0,
                    "fixed_vulns": 0,
                    "recid_vulns": 0,
                    "recid_type": 0,
                    "recid_mod": 0,
                    "recid_both": 0
                } 

        # Put the snapshots in order
        key_dates = []
        for key in data_manager[project]:
            key_dates.append(parser.parse(key))
        key_dates.sort()

        # Read the change data
        try:
            path = f"churn_results/{project}.json"
            with open(path, "r") as file:
                churn_data = json.load(file)
            if churn_data is None:
                print("ERROR: Error collecting change data for", project)
                continue
        except:
            print("ERROR: Change Data not available for", project)
            continue
        
        # Process the JSON data
        # Base commit
        t_add = 0
        t_del = 0
        t_tot = 0
        date = parser.parse(churn_data["datetime"])
        author = churn_data["commit_author"]
        for metric in churn_data["metrics"]:
            t_add += metric["lines_added"]
            t_del += metric["lines_deleted"]
            t_tot += metric["total_lines_changed"]
        # Base Commit - Determine Snapshot
        for snapshot_date in key_dates:
            if date < snapshot_date:
                key = str(snapshot_date)
                data_manager[project][key]["total_add"] += t_add
                data_manager[project][key]["total_del"] += t_del
                data_manager[project][key]["total_change"] += t_tot
                data_manager[project][key]["authors"].add(author)
                data_manager[project][key]["commits"] += 1
                break
        # History
        for commit in churn_data["history"]:
            t_add = 0
            t_del = 0
            t_tot = 0
            date = parser.parse(commit["datetime"])
            author = commit["commit_author"]
            for metric in commit["metrics"]:
                t_add += metric["lines_added"]
                t_del += metric["lines_deleted"]
                t_tot += metric["total_lines_changed"]
            for snapshot_date in key_dates:
                if date < snapshot_date:
                    key = str(snapshot_date)
                    data_manager[project][key]["total_add"] += t_add
                    data_manager[project][key]["total_del"] += t_del
                    data_manager[project][key]["total_change"] += t_tot
                    data_manager[project][key]["authors"].add(author)
                    data_manager[project][key]["commits"] += 1
                    break
        print("FINISHED: ", project)
    # Get Overall Stats
    overall_result_stats = {}
    for project in data_manager:
        temp_total_add = 0
        temp_total_del = 0
        temp_total_change = 0
        temp_authors = set()
        total_commits = 0
        for snap in data_manager[project]:
            temp_res = data_manager[project][snap]
            temp_total_add += temp_res["total_add"]
            temp_total_del += temp_res["total_del"]
            temp_total_change += temp_res["total_change"]
            temp_authors = temp_authors.union(temp_res["authors"])
            total_commits += temp_res["commits"]
        if total_commits == 0:
                # print(project)
                continue
        overall_result_stats[project] = {
            "total_add": temp_total_add,
            "total_add_per_commit": temp_total_add/total_commits,
            "total_del": temp_total_del,
            "total_del_per_commit": temp_total_del/total_commits,
            "total_change": temp_total_change,
            "total_change_per_commit": temp_total_change/total_commits,
            "authors": temp_authors,
            "author_count": len(temp_authors),
            "total_commits": total_commits,
            "fixed_vulns": 0,
            "recid_vulns": 0,
            "recid_type": 0,
            "recid_mod": 0,
            "recid_both": 0
        }
    # Get the Recidivism data
    for project in overall_result_stats:
        # Put the snapshots in order
        key_dates = []
        for key in data_manager[project]:
            key_dates.append(parser.parse(key))
        key_dates.sort()
        for cve in core_data[project]:
            recid = cve["fix_duplicate_type"] or cve["intro_duplicate_type"] or cve["file_fixed_before_fixed_again"] or cve["file_fixed_before_vuln_again"]
            recid_type = cve["fix_duplicate_type"] or cve["intro_duplicate_type"]
            recid_mod = cve["file_fixed_before_fixed_again"] or cve["file_fixed_before_vuln_again"]
            recid_both = recid_type and recid_mod

            target_date = parser.parse(cve["earliest_patch_date"])
            for date in key_dates:
                # Can also use this code to build up the snapshot records
                if target_date < date:
                    overall_result_stats[project]["fixed_vulns"] += 1
                    data_manager[project][str(date)]["fixed_vulns"] += 1
                    if recid:
                        overall_result_stats[project]["recid_vulns"] += 1
                        data_manager[project][str(date)]["recid_vulns"] += 1
                        if recid_type:
                            overall_result_stats[project]["recid_type"] += 1
                            data_manager[project][str(date)]["recid_type"] += 1
                        if recid_mod:
                            overall_result_stats[project]["recid_mod"] += 1
                            data_manager[project][str(date)]["recid_mod"] += 1
                        if recid_both:
                            overall_result_stats[project]["recid_both"] += 1
                            data_manager[project][str(date)]["recid_both"] += 1
                    break
    
    changes_per_commit = []
    adds_per_commit = []
    dels_per_commit = []
    author_count = []
    percent_overall = []
    percent_type = []
    percent_mod = []
    to_delete = []
    for project in core_data:
        try:
            adds_per_commit.append(overall_result_stats[project]["total_add_per_commit"])
            dels_per_commit.append(overall_result_stats[project]["total_del_per_commit"])
            changes_per_commit.append(overall_result_stats[project]["total_change_per_commit"])
            author_count.append(overall_result_stats[project]["author_count"])
            percent_overall.append(percent_data[project]["recid_percent_elig"])
            percent_type.append(percent_data[project]["type_percent_elig"])
            percent_mod.append(percent_data[project]["mod_percent_elig"])
        except:
            to_delete.append(project)

    # Changes
    print("\nChanges")
    corr, p_value = spearmanr(changes_per_commit, percent_overall)
    print(f"Spearman correlation Overall: {corr:.3f}, p-value: {p_value:.3g}")

    corr, p_value = spearmanr(changes_per_commit, percent_type)
    print(f"Spearman correlation Type: {corr:.3f}, p-value: {p_value:.3g}")

    corr, p_value = spearmanr(changes_per_commit, percent_mod)
    print(f"Spearman correlation Mod: {corr:.3f}, p-value: {p_value:.3g}")

    # Adds
    print("\nAdds")
    corr, p_value = spearmanr(adds_per_commit, percent_overall)
    print(f"Spearman correlation Overall: {corr:.3f}, p-value: {p_value:.3g}")

    corr, p_value = spearmanr(adds_per_commit, percent_type)
    print(f"Spearman correlation Type: {corr:.3f}, p-value: {p_value:.3g}")

    corr, p_value = spearmanr(adds_per_commit, percent_mod)
    print(f"Spearman correlation Mod: {corr:.3f}, p-value: {p_value:.3g}")
    
    # Deletes
    print("\nDeletes")
    corr, p_value = spearmanr(dels_per_commit, percent_overall)
    print(f"Spearman correlation Overall: {corr:.3f}, p-value: {p_value:.3g}")

    corr, p_value = spearmanr(dels_per_commit, percent_type)
    print(f"Spearman correlation Type: {corr:.3f}, p-value: {p_value:.3g}")

    corr, p_value = spearmanr(dels_per_commit, percent_mod)
    print(f"Spearman correlation Mod: {corr:.3f}, p-value: {p_value:.3g}")
    
    # Authors
    print("\nAuthors")
    corr, p_value = spearmanr(author_count, percent_overall)
    print(f"Spearman correlation Overall: {corr:.3f}, p-value: {p_value:.3g}")

    corr, p_value = spearmanr(author_count, percent_type)
    print(f"Spearman correlation Type: {corr:.3f}, p-value: {p_value:.3g}")

    corr, p_value = spearmanr(author_count, percent_mod)
    print(f"Spearman correlation Mod: {corr:.3f}, p-value: {p_value:.3g}")
    
    # Project by Project Analysis
    majority_adds_type = []
    majority_adds_mod = []
    majority_adds_none = 0

    majority_dels_type = []
    majority_dels_mod = []
    majority_dels_none = 0

    evens_type = []
    evens_mod = []
    evens_none = 0

    above_average_type = []
    above_average_mod = []
    above_average_none = 0

    below_average_type = []
    below_average_mod = []
    below_average_none = 0

    at_average_type = []
    at_average_mod = []
    at_average_none = 0

    for project in data_manager:
        authors = 0
        snaps = 0
        for shot in data_manager[project]:
            snaps += 1
            authors += len(data_manager[project][shot]["authors"])
        average_authors = authors/snaps
        for shot in data_manager[project]:
            if data_manager[project][shot]["total_change"] == 0:
                add_percent = 0
            else:
                add_percent = data_manager[project][shot]["total_add"]/data_manager[project][shot]["total_change"]
            snap_authors = len(data_manager[project][shot]["authors"])
            # Majority Add
            if add_percent > .5:
                if data_manager[project][shot]["fixed_vulns"] == 0 or data_manager[project][shot]["recid_vulns"] == 0:
                    majority_adds_none += 1
                else:
                    majority_adds_type.append(data_manager[project][shot]["recid_type"]/data_manager[project][shot]["fixed_vulns"])
                    majority_adds_mod.append(data_manager[project][shot]["recid_mod"]/data_manager[project][shot]["fixed_vulns"])
            elif add_percent == .5:
                # Evens
                if data_manager[project][shot]["fixed_vulns"] == 0 or data_manager[project][shot]["recid_vulns"] == 0:
                    evens_none += 1
                else:
                    evens_type.append(data_manager[project][shot]["recid_type"]/data_manager[project][shot]["fixed_vulns"])
                    evens_mod.append(data_manager[project][shot]["recid_mod"]/data_manager[project][shot]["fixed_vulns"])
            else:
                # Majority Dels
                if data_manager[project][shot]["fixed_vulns"] == 0 or data_manager[project][shot]["recid_vulns"] == 0:
                    majority_dels_none += 1
                else:
                    majority_dels_type.append(data_manager[project][shot]["recid_type"]/data_manager[project][shot]["fixed_vulns"])
                    majority_dels_mod.append(data_manager[project][shot]["recid_mod"]/data_manager[project][shot]["fixed_vulns"])
            # Authorships
            # Above Average
            if snap_authors > average_authors:
                if data_manager[project][shot]["fixed_vulns"] == 0 or data_manager[project][shot]["recid_vulns"] == 0:
                    above_average_none += 1
                else:
                    above_average_type.append(data_manager[project][shot]["recid_type"]/data_manager[project][shot]["fixed_vulns"])
                    above_average_mod.append(data_manager[project][shot]["recid_mod"]/data_manager[project][shot]["fixed_vulns"])
            elif snap_authors == average_authors:
                if data_manager[project][shot]["fixed_vulns"] == 0 or data_manager[project][shot]["recid_vulns"] == 0:
                    at_average_none += 1
                else:
                    at_average_type.append(data_manager[project][shot]["recid_type"]/data_manager[project][shot]["fixed_vulns"])
                    at_average_mod.append(data_manager[project][shot]["recid_mod"]/data_manager[project][shot]["fixed_vulns"])
            else:
                if data_manager[project][shot]["fixed_vulns"] == 0 or data_manager[project][shot]["recid_vulns"] == 0:
                    below_average_none += 1
                else:
                    below_average_type.append(data_manager[project][shot]["recid_type"]/data_manager[project][shot]["fixed_vulns"])
                    below_average_mod.append(data_manager[project][shot]["recid_mod"]/data_manager[project][shot]["fixed_vulns"])
    
    print("\n--Majority Additions--")
    print("Total Majority Adds Periods:", len(majority_adds_type) + len(majority_adds_mod) + majority_adds_none)
    print("Majority Adds Periods with 0 Recidivism:", majority_adds_none)
    print("Majority Adds Periods with Type Recidivism", len(majority_adds_type))
    try:
        print("Median Type Recid Rate Among Recidivistic Periods:", statistics.median(majority_adds_type))
        print("Mean Type Recid Rate Among Recidivistic Periods:", statistics.mean(majority_adds_type))
    except:
        pass
    print("Majority Adds Periods with Module Recidivism", len(majority_adds_mod))
    try:
        print("Median Module Recid Rate Among Recidivistic Periods:", statistics.median(majority_adds_mod))
        print("Mean Module Recid Rate Among Recidivistic Periods:", statistics.mean(majority_adds_mod))
    except:
        pass
    print()

    print("\n--Majority Deletions--")
    print("Total Majority Dels Periods:", len(majority_dels_type) + len(majority_dels_mod) + majority_dels_none)
    print("Majority Dels Periods with 0 Recidivism:", majority_dels_none)
    print("Majority Dels Periods with Type Recidivism", len(majority_dels_type))
    try:
        print("Median Type Recid Rate Among Recidivistic Periods:", statistics.median(majority_dels_type))
        print("Mean Type Recid Rate Among Recidivistic Periods:", statistics.mean(majority_dels_type))
    except:
        pass
    print("Majority Dels Periods with Module Recidivism", len(majority_dels_mod))
    try:
        print("Median Module Recid Rate Among Recidivistic Periods:", statistics.median(majority_dels_mod))
        print("Mean Module Recid Rate Among Recidivistic Periods:", statistics.mean(majority_dels_mod))
    except:
        pass
    print()

    print("\n--Even Additions/Deletions--")
    print("Total Even Periods:", len(evens_type) + len(evens_mod) + evens_none)
    print("Evens Periods with 0 Recidivism:", evens_none)
    print("Evens Periods with Type Recidivism", len(evens_type))
    try:
        print("Median Type Recid Rate Among Recidivistic Periods:", statistics.median(evens_type))
        print("Mean Type Recid Rate Among Recidivistic Periods:", statistics.mean(evens_type))
    except:
        pass
    print("Evens Periods with Module Recidivism", len(evens_mod))
    try:
        print("Median Module Recid Rate Among Recidivistic Periods:", statistics.median(evens_mod))
        print("Mean Module Recid Rate Among Recidivistic Periods:", statistics.mean(evens_mod))
    except:
        pass
    print()

    print("\n--Above Average Authors--")
    print("Total Above Average Authors Periods:", len(above_average_type) + len(above_average_mod) + above_average_none)
    print("Above Average Authors Periods with 0 Recidivism:", above_average_none)
    print("Above Average Authors Periods with Type Recidivism", len(above_average_type))
    try:
        print("Median Type Recid Rate Among Recidivistic Periods:", statistics.median(above_average_type))
        print("Mean Type Recid Rate Among Recidivistic Periods:", statistics.mean(above_average_type))
    except:
        pass
    print("Above Average Authors Periods with Module Recidivism", len(above_average_mod))
    try:
        print("Median Module Recid Rate Among Recidivistic Periods:", statistics.median(above_average_mod))
        print("Mean Module Recid Rate Among Recidivistic Periods:", statistics.mean(above_average_mod))
    except:
        pass
    print()

    print("\n--Below Average Authors--")
    print("Total Below Average Authors Periods:", len(below_average_type) + len(below_average_mod) + below_average_none)
    print("Below Average Authors Periods with 0 Recidivism:", below_average_none)
    print("Below Average Authors Periods with Type Recidivism", len(below_average_type))
    try:
        print("Median Type Recid Rate Among Recidivistic Periods:", statistics.median(below_average_type))
        print("Mean Type Recid Rate Among Recidivistic Periods:", statistics.mean(below_average_type))
    except:
        pass
    print("Below Average Authors Periods with Module Recidivism", len(below_average_mod))
    try:
        print("Median Module Recid Rate Among Recidivistic Periods:", statistics.median(below_average_mod))
        print("Mean Module Recid Rate Among Recidivistic Periods:", statistics.mean(below_average_mod))
    except:
        pass
    print()

    print("\n--At Average Authors--")
    print("Total At Average Authors Periods:", len(at_average_type) + len(at_average_mod) + at_average_none)
    print("At Average Authors Periods with 0 Recidivism:", at_average_none)
    print("At Average Authors Periods with Type Recidivism", len(at_average_type))
    try:
        print("Median Type Recid Rate Among Recidivistic Periods:", statistics.median(at_average_type))
        print("Mean Type Recid Rate Among Recidivistic Periods:", statistics.mean(at_average_type))
    except:
        pass
    print("At Average Authors Periods with Module Recidivism", len(at_average_mod))
    try:
        print("Median Module Recid Rate Among Recidivistic Periods:", statistics.median(at_average_mod))
        print("Mean Module Recid Rate Among Recidivistic Periods:", statistics.mean(at_average_mod))
    except:
        pass
    
def severity(core_data):
    v3map = {
        "attackVector":{
            "NETWORK": 4,
            "ADJACENT_NETWORK": 3,
            "LOCAL": 2,
            "PHYSICAL": 1
        },
        "attackComplexity":{
            "LOW": 2,
            "HIGH": 1
        },
        "privilegesRequired":{
            "NONE": 3,
            "LOW": 2,
            "HIGH": 1
        },
        "userInteraction":{
            "NONE": 2,
            "REQUIRED": 1
        },
        "scope":{
            "CHANGED": 2,
            "UNCHANGED": 1
        },
        "confidentialityImpact":{
            "HIGH": 3,
            "LOW": 2,
            "NONE": 1
        },
        "integrityImpact":{
            "HIGH": 3,
            "LOW": 2,
            "NONE": 1
        },
        "availabilityImpact":{
            "HIGH": 3,
            "LOW": 2,
            "NONE": 1
        }
    }
    v2map = {
        "accessVector": {
            "NETWORK": 3,
            "ADJACENT_NETWORK": 2,
            "LOCAL": 1
        },
        "accessComplexity": {
            "LOW": 3,
            "MEDIUM": 2,
            "HIGH": 1
        },
        "authentication": {
            "NONE": 3,
            "SINGLE": 2,
            "MULTIPLE": 1
        },
        "confidentialityImpact": {
            "COMPLETE": 3,
            "PARTIAL": 2,
            "NONE": 1
        },
        "integrityImpact": {
            "COMPLETE": 3,
            "PARTIAL": 2,
            "NONE": 1
        },
        "availabilityImpact": {
            "COMPLETE": 3,
            "PARTIAL": 2,
            "NONE": 1
        }
    }

    v30_results = {
        "attackVector": {
            "non": [],
            "recid": [],
            "type": [],
            "mod": []
        },
        "attackComplexity": {
            "non": [],
            "recid": [],
            "type": [],
            "mod": []
        },
        "privilegesRequired": {
            "non": [],
            "recid": [],
            "type": [],
            "mod": []
        },
        "userInteraction": {
            "non": [],
            "recid": [],
            "type": [],
            "mod": []
        },
        "scope": {
            "non": [],
            "recid": [],
            "type": [],
            "mod": []
        },
        "confidentialityImpact": {
            "non": [],
            "recid": [],
            "type": [],
            "mod": []
        },
        "integrityImpact": {
            "non": [],
            "recid": [],
            "type": [],
            "mod": []
        },
        "availabilityImpact": {
            "non": [],
            "recid": [],
            "type": [],
            "mod": []
        },
        "baseScore": {
            "non": [],
            "recid": [],
            "type": [],
            "mod": []
        }
    }
    v31_results = {
        "attackVector": {
            "non": [],
            "recid": [],
            "type": [],
            "mod": []
        },
        "attackComplexity": {
            "non": [],
            "recid": [],
            "type": [],
            "mod": []
        },
        "privilegesRequired": {
            "non": [],
            "recid": [],
            "type": [],
            "mod": []
        },
        "userInteraction": {
            "non": [],
            "recid": [],
            "type": [],
            "mod": []
        },
        "scope": {
            "non": [],
            "recid": [],
            "type": [],
            "mod": []
        },
        "confidentialityImpact": {
            "non": [],
            "recid": [],
            "type": [],
            "mod": []
        },
        "integrityImpact": {
            "non": [],
            "recid": [],
            "type": [],
            "mod": []
        },
        "availabilityImpact": {
            "non": [],
            "recid": [],
            "type": [],
            "mod": []
        },
        "baseScore": {
            "non": [],
            "recid": [],
            "type": [],
            "mod": []
        }
    }
    v3combined_results = {
        "attackVector": {
            "non": [],
            "recid": [],
            "type": [],
            "mod": []
        },
        "attackComplexity": {
            "non": [],
            "recid": [],
            "type": [],
            "mod": []
        },
        "privilegesRequired": {
            "non": [],
            "recid": [],
            "type": [],
            "mod": []
        },
        "userInteraction": {
            "non": [],
            "recid": [],
            "type": [],
            "mod": []
        },
        "scope": {
            "non": [],
            "recid": [],
            "type": [],
            "mod": []
        },
        "confidentialityImpact": {
            "non": [],
            "recid": [],
            "type": [],
            "mod": []
        },
        "integrityImpact": {
            "non": [],
            "recid": [],
            "type": [],
            "mod": []
        },
        "availabilityImpact": {
            "non": [],
            "recid": [],
            "type": [],
            "mod": []
        },
        "baseScore": {
            "non": [],
            "recid": [],
            "type": [],
            "mod": []
        }
    }
    v2_results = {
        "accessVector": {
            "non": [],
            "recid": [],
            "type": [],
            "mod": []
        },
        "accessComplexity": {
            "non": [],
            "recid": [],
            "type": [],
            "mod": []
        },
        "authentication": {
            "non": [],
            "recid": [],
            "type": [],
            "mod": []
        },
        "confidentialityImpact": {
            "non": [],
            "recid": [],
            "type": [],
            "mod": []
        }, 
        "integrityImpact": {
            "non": [],
            "recid": [],
            "type": [],
            "mod": []
        }, 
        "availabilityImpact": {
            "non": [],
            "recid": [],
            "type": [],
            "mod": []
        }, 
        "baseScore": {
            "non": [],
            "recid": [],
            "type": [],
            "mod": []
        } 
    }

    for project in core_data:
        for cve in core_data[project]:
            recid = cve["fix_duplicate_type"] or cve["intro_duplicate_type"] or cve["file_fixed_before_fixed_again"] or cve["file_fixed_before_vuln_again"]
            rtype = cve["fix_duplicate_type"] or cve["intro_duplicate_type"]
            rmod = ["file_fixed_before_fixed_again"] or cve["file_fixed_before_vuln_again"]


            if "baseMetricV3" in cve["impact"]:
                # handle v3 scenarios
                if cve["impact"]["baseMetricV3"]["cvssV3"]["version"] == "3.1":
                    # handle v3.1
                    for key in v31_results:
                        val = None
                        if key != "baseScore":
                            val = v3map[key][cve["impact"]["baseMetricV3"]["cvssV3"][key]]
                        else:
                            val = cve["impact"]["baseMetricV3"]["cvssV3"][key]
                        if recid:
                            v31_results[key]["recid"].append(val)
                            v3combined_results[key]["recid"].append(val)
                            if rtype:
                                v31_results[key]["type"].append(val)
                                v3combined_results[key]["type"].append(val)
                            if rmod:
                                v31_results[key]["mod"].append(val)
                                v3combined_results[key]["mod"].append(val)                                
                        else:
                            v31_results[key]["non"].append(val)
                            v3combined_results[key]["non"].append(val)
                else:
                    # handle v3.0
                    for key in v30_results:
                        val = None
                        if key != "baseScore":
                            val = v3map[key][cve["impact"]["baseMetricV3"]["cvssV3"][key]]
                        else:
                            val = cve["impact"]["baseMetricV3"]["cvssV3"][key]
                        if recid:
                            v30_results[key]["recid"].append(val)
                            v3combined_results[key]["recid"].append(val)
                            if rtype:
                                v30_results[key]["type"].append(val)
                                v3combined_results[key]["type"].append(val)
                            if rmod:
                                v30_results[key]["mod"].append(val)
                                v3combined_results[key]["mod"].append(val)                                
                        else:
                            v30_results[key]["non"].append(val)
                            v3combined_results[key]["non"].append(val)

            if "baseMetricV2" in cve["impact"]:
                # handle v2 scenario
                if cve["impact"]["baseMetricV2"]["cvssV2"]["version"] == "2.0":
                    # handle v2.0
                    for key in v2_results:
                        val = None
                        if key != "baseScore":
                            val = v2map[key][cve["impact"]["baseMetricV2"]["cvssV2"][key]]
                        else:
                            val = cve["impact"]["baseMetricV2"]["cvssV2"][key]
                        if recid:
                            v2_results[key]["recid"].append(val)
                            if rtype:
                                v2_results[key]["type"].append(val)
                            if rmod:
                                v2_results[key]["mod"].append(val)
                        else:
                            v2_results[key]["non"].append(val)  
    
    # V30 MWW
    print("\n--V3.0--")
    for key in v30_results:
        print("MWW Key:", key, "Recid-Non")
        print("Median Non:", statistics.median(v30_results[key]["non"]))
        print("Mean Non:", statistics.mean(v30_results[key]["non"]))
        print("Median Recid:", statistics.median(v30_results[key]["recid"]))
        print("Mean Recid:", statistics.mean(v30_results[key]["recid"]))
        stat, p_value = mannwhitneyu(v30_results[key]["recid"], v30_results[key]["non"])
        print(f"Recid-Non P-Value: {p_value}")
        print()
        print("MWW Key:", key, "Type-Non")
        print("Median Type:", statistics.median(v30_results[key]["type"]))
        print("Mean Type:", statistics.mean(v30_results[key]["type"]))
        stat, p_value = mannwhitneyu(v30_results[key]["type"], v30_results[key]["non"])
        print(f"Type-Non P-Value: {p_value}")
        print()
        print("MWW Key:", key, "Mod-Non")
        print("Median Mod:", statistics.median(v30_results[key]["mod"]))
        print("Mean Mod:", statistics.mean(v30_results[key]["mod"]))
        stat, p_value = mannwhitneyu(v30_results[key]["mod"], v30_results[key]["non"])
        print(f"Mod-Non P-Value: {p_value}")
        print()

    # V31 MWW
    print("\n--V3.1--")
    for key in v31_results:
        print("MWW Key:", key, "Recid-Non")
        print("Median Non:", statistics.median(v31_results[key]["non"]))
        print("Mean Non:", statistics.mean(v31_results[key]["non"]))
        print("Median Recid:", statistics.median(v31_results[key]["recid"]))
        print("Mean Recid:", statistics.mean(v31_results[key]["recid"]))
        stat, p_value = mannwhitneyu(v31_results[key]["recid"], v31_results[key]["non"])
        print(f"Recid-Non P-Value: {p_value}")
        print()
        print("MWW Key:", key, "Type-Non")
        print("Median Type:", statistics.median(v31_results[key]["type"]))
        print("Mean Type:", statistics.mean(v31_results[key]["type"]))
        stat, p_value = mannwhitneyu(v31_results[key]["type"], v31_results[key]["non"])
        print(f"Type-Non P-Value: {p_value}")
        print()
        print("MWW Key:", key, "Mod-Non")
        print("Median Mod:", statistics.median(v31_results[key]["mod"]))
        print("Mean Mod:", statistics.mean(v31_results[key]["mod"]))
        stat, p_value = mannwhitneyu(v31_results[key]["mod"], v31_results[key]["non"])
        print(f"Mod-Non P-Value: {p_value}")
        print()

    # V3C MWW
    print("\n--V3.X--")
    for key in v3combined_results:
        print("MWW Key:", key, "Recid-Non")
        print("Median Non:", statistics.median(v3combined_results[key]["non"]))
        print("Mean Non:", statistics.mean(v3combined_results[key]["non"]))
        print("Median Recid:", statistics.median(v3combined_results[key]["recid"]))
        print("Mean Recid:", statistics.mean(v3combined_results[key]["recid"]))
        stat, p_value = mannwhitneyu(v3combined_results[key]["recid"], v3combined_results[key]["non"])
        print(f"Recid-Non P-Value: {p_value}")
        print()
        print("MWW Key:", key, "Type-Non")
        print("Median Type:", statistics.median(v3combined_results[key]["type"]))
        print("Mean Type:", statistics.mean(v3combined_results[key]["type"]))
        stat, p_value = mannwhitneyu(v3combined_results[key]["type"], v3combined_results[key]["non"])
        print(f"Type-Non P-Value: {p_value}")
        print()
        print("MWW Key:", key, "Mod-Non")
        print("Median Mod:", statistics.median(v3combined_results[key]["mod"]))
        print("Mean Mod:", statistics.mean(v3combined_results[key]["mod"]))
        stat, p_value = mannwhitneyu(v3combined_results[key]["mod"], v3combined_results[key]["non"])
        print(f"Mod-Non P-Value: {p_value}")
        print()

    # V2
    print("\n--V2.0--")
    for key in v2_results:
        print("MWW Key:", key, "Recid-Non")
        print("Median Non:", statistics.median(v2_results[key]["non"]))
        print("Mean Non:", statistics.mean(v2_results[key]["non"]))
        print("Median Recid:", statistics.median(v2_results[key]["recid"]))
        print("Mean Recid:", statistics.mean(v2_results[key]["recid"]))
        stat, p_value = mannwhitneyu(v2_results[key]["recid"], v2_results[key]["non"])
        print(f"Recid-Non P-Value: {p_value}")
        print()
        print("MWW Key:", key, "Type-Non")
        print("Median Type:", statistics.median(v2_results[key]["type"]))
        print("Mean Type:", statistics.mean(v2_results[key]["type"]))
        stat, p_value = mannwhitneyu(v2_results[key]["type"], v2_results[key]["non"])
        print(f"Type-Non P-Value: {p_value}")
        print()
        print("MWW Key:", key, "Mod-Non")
        print("Median Mod:", statistics.median(v2_results[key]["mod"]))
        print("Mean Mod:", statistics.mean(v2_results[key]["mod"]))
        stat, p_value = mannwhitneyu(v2_results[key]["mod"], v2_results[key]["non"])
        print(f"Mod-Non P-Value: {p_value}")
        print()

def subtypes(data):
    # Type -> Module -> Quantity at combo
    results = {
        "OAF": {
            "OAF":0,
            "FAF":0,
            "NON":0
        },
        "FAF": {
            "OAF":0,
            "FAF":0,
            "NON":0
        },
        "NON": {
            "OAF":0,
            "FAF":0,
            "NON":0
        }
    }

    for project in data:
        if len(data[project]) < 2:
            continue
        for cve in data[project]:
            tr_str = ""
            mr_str = ""
            if cve["intro_duplicate_type"]:
                tr_str = "OAF"
            elif cve["fix_duplicate_type"]:
                tr_str = "FAF"
            else:
                tr_str = "NON"

            if cve["file_fixed_before_vuln_again"]:
                mr_str = "OAF"
            elif cve["file_fixed_before_fixed_again"]:
                mr_str = "FAF"
            else:
                mr_str = "NON"
            results[tr_str][mr_str] += 1

    print(results["OAF"]["OAF"], results["OAF"]["FAF"], results["OAF"]["NON"])
    print(results["FAF"]["OAF"], results["FAF"]["FAF"], results["FAF"]["NON"])
    print(results["NON"]["OAF"], results["NON"]["FAF"], results["NON"]["NON"])



def main():
    res = build_dict_init("cve_with_cwe")
    # result_percents = prev_stats_overall(res)
    # complexity(result_percents, res)
    # changes_and_authorship(res, result_percents)
    # severity(res)
    subtypes(res)



if __name__ == '__main__':
    main()