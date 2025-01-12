import collections

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