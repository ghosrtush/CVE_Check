import nvdlib
import datetime
import csv

end = datetime.datetime.now()
end_clean = end.replace(microsecond=0, second=0)

start = end - datetime.timedelta(days=120)
start_clean = start.replace(microsecond=0, second=0)


software = open("Software.txt", 'r')
software_list = software.read().splitlines()
for i in software_list:
    r = nvdlib.searchCVE(pubStartDate=start_clean, pubEndDate=end_clean, keywordSearch=i,
                         key='#')
    with open('CVE_list.csv', 'a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["CVE ID", "Ref", "Score", "Description"])
        for eachCVE in r:
            writer.writerow([eachCVE.id, eachCVE.url, str(eachCVE.score[1]), eachCVE.descriptions[0].value])
software.close()
