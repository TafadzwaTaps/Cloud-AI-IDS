import pandas as pd
import os

DATASET_FOLDER = "MachineLearningCSV"

csv_files = [
    "Monday-WorkingHours.pcap_ISCX.csv",
    "Tuesday-WorkingHours.pcap_ISCX.csv",
    "Wednesday-workingHours.pcap_ISCX.csv",
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
    "Friday-WorkingHours-Morning.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"
]

dataframes = []

for file in csv_files:
    file_path = os.path.join(DATASET_FOLDER, file)
    print(f"Loading: {file_path}")

    df = pd.read_csv(file_path)
    dataframes.append(df)

merged_df = pd.concat(dataframes, ignore_index=True)

merged_df.to_csv("CIC_IDS_2017.csv", index=False)

print("✅ CIC_IDS_2017.csv created successfully!")
print("Dataset shape:", merged_df.shape)
