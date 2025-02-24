import pandas as pd
import numpy as np
import seaborn as sns
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.neural_network import MLPClassifier
from xgboost import XGBClassifier
from sklearn.svm import SVC
import keras
from keras.layers import Input, Dense
from keras import regularizers
from keras.models import Model
import pickle
import os

# Set the working directory to where your script is located
script_dir = os.path.dirname(os.path.abspath(__file__))
os.chdir(script_dir)

# Load the data
data_path = r"Q:\Documents\HSHL Studium\sem 6\AI\Phising website detection\Dataset\phishing_detection_dataset.csv"
data0 = pd.read_csv(data_path)

# Data Preprocessing
data = data0.drop(['Domain'], axis=1).copy()
data = data.sample(frac=1).reset_index(drop=True)

# Splitting the Data
y = data['Label']
X = data.drop('Label', axis=1)
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=12)

# Function to store results
ML_Model, acc_train, acc_test = [], [], []
def storeResults(model, a, b):
    ML_Model.append(model)
    acc_train.append(round(a, 3))
    acc_test.append(round(b, 3))

# 1. Decision Tree Classifier
tree = DecisionTreeClassifier(max_depth=5)
tree.fit(X_train, y_train)
y_test_tree = tree.predict(X_test)
y_train_tree = tree.predict(X_train)
acc_train_tree = accuracy_score(y_train, y_train_tree)
acc_test_tree = accuracy_score(y_test, y_test_tree)
storeResults('Decision Tree', acc_train_tree, acc_test_tree)

# 2. Random Forest Classifier
forest = RandomForestClassifier(max_depth=5)
forest.fit(X_train, y_train)
y_test_forest = forest.predict(X_test)
y_train_forest = forest.predict(X_train)
acc_train_forest = accuracy_score(y_train, y_train_forest)
acc_test_forest = accuracy_score(y_test, y_test_forest)
storeResults('Random Forest', acc_train_forest, acc_test_forest)

# 3. Multilayer Perceptrons
mlp = MLPClassifier(alpha=0.001, hidden_layer_sizes=([100,100,100]))
mlp.fit(X_train, y_train)
y_test_mlp = mlp.predict(X_test)
y_train_mlp = mlp.predict(X_train)
acc_train_mlp = accuracy_score(y_train, y_train_mlp)
acc_test_mlp = accuracy_score(y_test, y_test_mlp)
storeResults('Multilayer Perceptrons', acc_train_mlp, acc_test_mlp)

# 4. XGBoost Classifier
xgb = XGBClassifier(learning_rate=0.4, max_depth=7)
xgb.fit(X_train, y_train)
y_test_xgb = xgb.predict(X_test)
y_train_xgb = xgb.predict(X_train)
acc_train_xgb = accuracy_score(y_train, y_train_xgb)
acc_test_xgb = accuracy_score(y_test, y_test_xgb)
storeResults('XGBoost', acc_train_xgb, acc_test_xgb)

# 5. Autoencoder Neural Network
input_dim = X_train.shape[1]
encoding_dim = input_dim
input_layer = Input(shape=(input_dim, ))
encoder = Dense(encoding_dim, activation="relu", activity_regularizer=regularizers.l1(10e-4))(input_layer)
encoder = Dense(int(encoding_dim), activation="relu")(encoder)
encoder = Dense(int(encoding_dim-2), activation="relu")(encoder)
code = Dense(int(encoding_dim-4), activation='relu')(encoder)
decoder = Dense(int(encoding_dim-2), activation='relu')(code)
decoder = Dense(int(encoding_dim), activation='relu')(encoder)
decoder = Dense(input_dim, activation='relu')(decoder)
autoencoder = Model(inputs=input_layer, outputs=decoder)
autoencoder.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
history = autoencoder.fit(X_train, X_train, epochs=10, batch_size=64, shuffle=True, validation_split=0.2)
acc_train_auto = autoencoder.evaluate(X_train, X_train)[1]
acc_test_auto = autoencoder.evaluate(X_test, X_test)[1]
storeResults('AutoEncoder', acc_train_auto, acc_test_auto)

# 6. Support Vector Machines
svm = SVC(kernel='linear', C=1.0, random_state=12)
svm.fit(X_train, y_train)
y_test_svm = svm.predict(X_test)
y_train_svm = svm.predict(X_train)
acc_train_svm = accuracy_score(y_train, y_train_svm)
acc_test_svm = accuracy_score(y_test, y_test_svm)
storeResults('SVM', acc_train_svm, acc_test_svm)

# Comparison of Models
results = pd.DataFrame({
    'ML Model': ML_Model,
    'Train Accuracy': acc_train,
    'Test Accuracy': acc_test
})
print(results.sort_values(by=['Test Accuracy', 'Train Accuracy'], ascending=False))

# Save the best model (XGBoost in this case)
pickle.dump(xgb, open("XGBoostClassifier.pickle.dat", "wb"))

# Test the saved model
loaded_model = pickle.load(open("XGBoostClassifier.pickle.dat", "rb"))
print("Loaded model:", loaded_model)

# Visualizations
plt.figure(figsize=(15,15))
data.hist(bins=50)
plt.tight_layout()
plt.savefig('data_distribution.png')

plt.figure(figsize=(15,13))
sns.heatmap(data.corr())
plt.tight_layout()
plt.savefig('correlation_heatmap.png')

# Feature importance for Decision Tree
plt.figure(figsize=(9,7))
n_features = X_train.shape[1]
plt.barh(range(n_features), tree.feature_importances_, align='center')
plt.yticks(np.arange(n_features), X_train.columns)
plt.xlabel("Feature importance")
plt.ylabel("Feature")
plt.tight_layout()
plt.savefig('decision_tree_feature_importance.png')

# Feature importance for Random Forest
plt.figure(figsize=(9,7))
plt.barh(range(n_features), forest.feature_importances_, align='center')
plt.yticks(np.arange(n_features), X_train.columns)
plt.xlabel("Feature importance")
plt.ylabel("Feature")
plt.tight_layout()
plt.savefig('random_forest_feature_importance.png')

print("Analysis complete. Check the current directory for output files and visualizations.")