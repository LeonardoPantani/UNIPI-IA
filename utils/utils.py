import collections

import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score, roc_auc_score
from sklearn.model_selection import StratifiedKFold


def printInfo(type, data):
    # Crea un oggetto Counter a partire dall'array
    counter = collections.Counter(data)
    # Calcola il numero di elementi per ogni intero
    counts = dict(counter)
    # Calcola la percentuale rispetto al totale nell'array
    percentages = {k: v / len(data) for k, v in counts.items()}
    # Stampa i risultati
    print("Esempi di {} [tot: {}]:".format(type, len(data)))
    for k,v in counts.items():
        print(" Classe {}: {} ({:.2f}% del totale)".format(k, v, percentages[k]*100))



def evaluate_model_with_cv(x_train, y_train, classifier, x_test=None, y_test=None, target_names=['benign', 'phishing', 'defacement', 'malware'], k=5, need_results=False):
    """
    Perform Stratified K-Fold Cross Validation and evaluate the model.

    Parameters:
    - x_train: Features for training.
    - y_train: Labels for training.
    - classifier: Model to be trained and evaluated.
    - x_test: (Optional) Features for testing.
    - y_test: (Optional) Labels for testing.
    - target_names: (Optional) List containing list of classes' names, default ['benign', 'phishing', 'defacement', 'malware'] 
    - k: (Optional) Number of folds, default 5
    - need_results: (Optional) Set this to True if results as dictionary are needed.

    Returns (if need_result=True):
    - A dictionary containing cross-validation metrics and optional test evaluation results.
    """

    # Stratified K-Fold Cross Validation
    stratified_kfold = StratifiedKFold(n_splits=k, shuffle=True)

    # Store cross-validation results
    cv_accuracy = []
    cv_f1 = []
    cv_auc = []

    for train_index, val_index in stratified_kfold.split(x_train, y_train):
        x_train_fold, x_val_fold = x_train.iloc[train_index], x_train.iloc[val_index]
        y_train_fold, y_val_fold = y_train.iloc[train_index], y_train.iloc[val_index]

        # Train the model on the current fold
        classifier.fit(x_train_fold, y_train_fold)

        # Predictions
        y_val_pred = classifier.predict(x_val_fold)
        y_val_proba = classifier.predict_proba(x_val_fold)

        # Metrics
        cv_accuracy.append(accuracy_score(y_val_fold, y_val_pred))
        cv_f1.append(f1_score(y_val_fold, y_val_pred, average='weighted'))
        cv_auc.append(roc_auc_score(y_val_fold, y_val_proba, multi_class='ovr'))

    # Cross-validation results
    cv_results = {
        "mean_accuracy": np.mean(cv_accuracy),
        "std_accuracy": np.std(cv_accuracy),
        "mean_f1": np.mean(cv_f1),
        "std_f1": np.std(cv_f1),
        "mean_auc": np.mean(cv_auc),
        "std_auc": np.std(cv_auc)
    }

    print("Stratified K-Fold Cross Validation Results:")
    print(f"Mean Accuracy: {cv_results['mean_accuracy']:.4f} ± {cv_results['std_accuracy']:.4f}")
    print(f"Mean F1 Score: {cv_results['mean_f1']:.4f} ± {cv_results['std_f1']:.4f}")
    print(f"Mean AUC Score: {cv_results['mean_auc']:.4f} ± {cv_results['std_auc']:.4f}")

    # Test evaluation (if test data is provided)
    if x_test is not None and y_test is not None:
        y_pred = classifier.predict(x_test)
        y_pred_proba = classifier.predict_proba(x_test)

        # Classification report
        report = classification_report(y_test, y_pred, target_names=target_names)
        print("\nClassification Report:")
        print(report)

        # AUC score
        auc_score = roc_auc_score(y_test, y_pred_proba, multi_class='ovr')
        print(f"\nAUC Score: {auc_score:.4f}")

        # Confusion Matrix
        conf_matrix = confusion_matrix(y_test, y_pred, labels=np.unique(y_test))
        plt.figure(figsize=(6, 4))
        sns.heatmap(conf_matrix, annot=True, fmt='d', cmap='Blues', xticklabels=target_names, yticklabels=target_names)
        plt.xlabel('Predicted Class')
        plt.ylabel('True Class')
        plt.title('Confusion Matrix')
        plt.show()

        cv_results["test_classification_report"] = report
        cv_results["test_auc_score"] = auc_score
        cv_results["test_confusion_matrix"] = conf_matrix

    return cv_results if need_results else None
