#!/usr/bin/python3
import pandas as pd
import numpy as np
import seaborn as sns
import matplotlib.pyplot as plt
from sklearn.feature_selection import VarianceThreshold
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler

# Load dataset
df = pd.read_csv("cleaned_data.csv")

# Remove leading/trailing spaces from column names
df.columns = df.columns.str.strip()

# Fill missing values
df = df.fillna(0)

# Pick the label column //checking the column name
if 'Encoded Labels' in df.columns:
    label_col = 'Encoded Labels'
elif 'Label' in df.columns:
    label_col = 'Label'
else:
    raise ValueError("No label column found.")

# Separate features and target //here we are removing the encoded label column
# so that x will only contain the features (independent var)
X = df.drop(columns=[label_col])
y = df[label_col]  # here encode label is the dependent var

# Keep only numeric columns for features
X = X.select_dtypes(include=[np.number]) # from that previous x frame

# 1. Remove low variance features
vt = VarianceThreshold(threshold=0.01)   # features with variance <=0.01 are dropped
X = X.loc[:, vt.fit(X).get_support()]

# 2. Remove highly correlated features
corr_matrix = X.corr()  # prepares a matrix where each entry is the correlation btn 2 features (auto-calculated)
threshold = 0.9  # if >0.9 then those 2 features are too simmilar
upper = corr_matrix.where(np.triu(np.ones(corr_matrix.shape), k=1).astype(bool)) #as the matrix has symmetric corr values, i.e (ab) and (ba) . so we masked the upper triangular matrix 
to_drop = [column for column in upper.columns if any(upper[column].abs() > threshold)] #here we dropped those columns whose corr value> 0.9 (only of the column)
X = X.drop(columns=to_drop) # after dropping the correlated features (now new features in X)

# Plot reduced correlation heatmap
plt.figure(figsize=(12, 8))
sns.heatmap(X.corr(), cmap='coolwarm') # again found the correlation
plt.title("Correlation Heatmap After Feature Reduction")
plt.show()  # red ---> blue (1-->0)

# 3. Feature importance (Random Forest)
rf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1) # n_estimate=no of trees , 42 reproducible results and cpu=1(n_jobs)
rf.fit(X, y)  #train the forest of 100 trees on basis of x to get y
importances = pd.Series(rf.feature_importances_, index=X.columns)
importances.sort_values(ascending=False).head(20).plot(kind='bar', title='Top 7 Features')
plt.show()

# 4. Standardization
scaler = StandardScaler()  # prepares z-score for each feature (x-mean)/deviation
X_scaled = scaler.fit_transform(X)  # took each values from every features and then calculated z score. z score is how far those data values from the mean is expressed in terms of standard deviation. std devn(spread of the dataset)
# X_scaled is a numpy array

# Save processed dataset
processed_df = pd.DataFrame(X_scaled, columns=X.columns) #converted x_scaled numpy array into a dataframe
processed_df['Label'] = y #appended the target y into the csv
processed_df.to_csv("processed_data.csv", index=False)


