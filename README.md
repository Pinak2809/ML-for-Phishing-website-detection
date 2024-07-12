# Phishing Website Detection using Machine Learning

## Objective
This project aims to develop and compare various machine learning models for detecting phishing websites. We collect both phishing and legitimate URLs to create a comprehensive dataset, extract relevant features, and train multiple models to predict whether a given URL is phishing or legitimate.

## Data Collection
We use three main data sources:

1. **PhishTank**: A set of phishing URLs from [PhishTank](http://data.phishtank.com/data/online-valid.csv.bz2). We use 5000 random phishing URLs from this dataset.

2. **Tranco List**: A list of popular legitimate domains from [Tranco](https://tranco-list.eu/top-1m.csv.zip).

3. **Majestic Million**: Another list of popular legitimate domains from [Majestic](https://downloads.majestic.com/majestic_million.csv).

These datasets are downloaded and processed using the `Download_Datasets.py` script in this repository.

## Feature Extraction
We extract various features from the URLs, including:
- Address Bar based Features
- Domain based Features
- HTML & JavaScript based Features

The feature extraction process is detailed in the `Phishing Website Detection_Feature Extraction.py` script.

## Models & Training
We split the data into 80% training and 20% testing sets. The following supervised machine learning models are trained and evaluated:

1. Decision Tree
2. Random Forest
3. Multilayer Perceptrons
4. XGBoost
5. Autoencoder Neural Network
6. Support Vector Machines

The model training and evaluation process is implemented in the `Phishing Website Detection_Models & Training.py` script.

## Results
The performance of each model is measured and compared. The results are as follows:

Copy             ML Model  Train Accuracy  Test Accuracy  Loss    val_loss
1           Random Forest         0.991         0.999     0.3391  0.2384
2  Multilayer Perceptrons         0.991         0.999     0.2217  0.1040
0           Decision Tree         0.991         0.998     0.1723  0.1506
5                     SVM         0.991         0.998     0.1535  0.1362
3                 XGBoost         0.990         0.998     0.1252  0.1230
4             AutoEncoder         0.364         0.359     0.1098  0.1134

The Random Forest and Multilayer Perceptrons models show the best performance with 99.9% test accuracy.

## Files in the Repository
- `Download_Datasets.py`: Script to download and process the datasets.
- `Phishing Website Detection_Feature Extraction.py`: Script for extracting features from URLs.
- `Phishing Website Detection_Models & Training.py`: Script for training and evaluating the models.
- `XGBoostClassifier.pickle.dat`: Saved XGBoost model (best performing model).

## How to Use
1. Clone the repository.
2. Run `Download_Datasets.py` to get the latest datasets.
3. Run `Phishing Website Detection_Feature Extraction.py` to extract features.
4. Run `Phishing Website Detection_Models & Training.py` to train and evaluate the models.

## Requirements
- Python 3.x
- Libraries: pandas, numpy, scikit-learn, xgboost, keras, tensorflow

## Future Work
- Implement cross-validation for more robust performance estimation.
- Explore ensemble methods combining the top-performing models.
- Develop a browser extension or GUI for real-time phishing detection.

## Contributors
Pinak Ganatra 1210339
