import pandas as pda
import numpy as npy
dframe=pda.read_csv('Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv')
print("______________")
print(dframe.isnull().sum())  #check any null values
dframe=dframe.dropna()  #updated data frame with removed missing values
#dframe.drop(['','','','','','','Init_Win_bytes_forward',' Idle Max',' Idle Min',' Active Max',' Active Min',
#' Init_Win_bytes_backward',' Active Std',' Idle Std',' Avg Fwd Segment Size',' Avg Bwd Segment Size',
#' Packet Length Std',' Packet Length Variance',' Bwd PSH Flags',' Fwd URG Flags',' Bwd URG Flags','FIN Flag Count',
#' SYN Flag Count',' URG Flag Count',' RST Flag Count',' ACK Flag Count',' CWE Flag Count',' ECE Flag Count',' Down/Up Ratio','Fwd Avg Bytes/Bulk',' Fwd Avg Packets/Bulk',' Fwd Avg Bulk Rate',' Bwd Avg Bytes/Bulk',' Bwd Avg Packets/Bulk','Bwd Avg Bulk Rate',' PSH Flag Count'],axis=1,inplace=True)
#we can just select the needed columns
dframe=dframe[[' Destination Port',' Flow Duration',' Total Fwd Packets',' Total Backward Packets',' Fwd Packet Length Mean',' Bwd Packet Length Mean','Flow Bytes/s',' Packet Length Mean','Active Mean','Label']]
print(dframe.columns)  #current coulumns present
  #at last we have to write this dframe to csv file
print("Encoding Labels i.e BENIGN-0 || Brute Force-1 || XSS-2 || Sql Injection-3")
print("  ")
print("*******************************")
dframe['Encoded Labels']=dframe[' Label'].map({'BENIGN':0,'Web Attack --> Brute Force':1,'Web Attack --> XSS':2,'Web Attack --> Sql Injection':3})
# At last we have to take 20 elements of each Label by grouping
sampled_frame=dframe.groupby('Encoded Labels').sample(n=20,random_state=42)
print(sampled_frame['Encoded Labels'].value_counts())
print(sampled_frame)
sampled_frame.to_csv('Sampled frame.csv',index=False)
dframe.to_csv('cleaned_data.csv',index=False)

