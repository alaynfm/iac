import csv
import glob

def process_csv(file_path, txt_file, CKV):
    
    with open(file_path, mode='r') as csv_file:
        csv_reader = csv.DictReader(csv_file)
        for row in csv_reader:
            if row['Misconfigurations']:
                txt_file.write(f"Misconfigurations: {row['Misconfigurations']}\n")
                txt_file.write(f"Resource: {row['Resource']}\n")
                txt_file.write(f"Path: {row['Path']}\n")
                txt_file.write(f"Severity: {row['Severity']}\n")
                txt_file.write(f"Policy title: {row['Policy title']}\n")
                txt_file.write(f"Guideline: {row['Guideline']}\n")
                txt_file.write("-------------------\n")
                CKV += f"{row['Misconfigurations']}\n"
    return CKV

def main():
    output_file = 'failed_CKV_Detailed.txt'
    output_file_list = 'failed_CKV.txt'
    CKV = ""
    with open(output_file, mode='w') as txt_file:
        for file_path in glob.glob('*iac.csv'):
            CKV = process_csv(file_path, txt_file, CKV)
    with open(output_file_list, mode='w') as txt_file:
        txt_file.write(CKV)

if __name__ == "__main__":
    main()
