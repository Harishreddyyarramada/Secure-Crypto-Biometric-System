from tkinter import messagebox, simpledialog, filedialog
from tkinter import *
import os
import numpy as np
import cv2
import matplotlib.pyplot as plt
from sklearn.decomposition import PCA
from sklearn.mixture import GaussianMixture
import pickle
from ecies.utils import generate_eth_key, generate_key
from ecies import encrypt, decrypt
import pyaes, pbkdf2, binascii, secrets
from sklearn.metrics import accuracy_score
import time
from PIL import Image, ImageTk
# Initialize main window
main = Tk()
main.title("Secure Crypto-Biometric System for Cloud Computing")
main.geometry("1300x1200")

# Global variables
global filename, pathlabel
global X, Y, encoder, pca, gmm
global labels
global ecc_publicKey, ecc_privateKey
global aes_time, ecc_time

# Define each function needed in the GUI
def ECCEncrypt(obj):
    enc = encrypt(ecc_publicKey, obj)
    return enc

def ECCDecrypt(obj):
    dec = decrypt(ecc_privateKey, obj)
    return dec

def generateKey():
    global ecc_publicKey, ecc_privateKey
    eth_k = generate_eth_key()
    ecc_privateKey = eth_k.to_hex()
    ecc_publicKey = eth_k.public_key.to_hex()
    return ecc_privateKey, ecc_publicKey

def getAesKey():
    password = "s3cr3t*c0d3"
    passwordSalt = '76895'
    key = pbkdf2.PBKDF2(password, passwordSalt).read(32)
    return key

def Aesencrypt(plaintext):
    aes = pyaes.AESModeOfOperationCTR(getAesKey(), pyaes.Counter(31129547035000047302952433967654195398124239844566322884172163637846056248223))
    ciphertext = aes.encrypt(plaintext)
    return ciphertext

def Aesdecrypt(enc):
    aes = pyaes.AESModeOfOperationCTR(getAesKey(), pyaes.Counter(31129547035000047302952433967654195398124239844566322884172163637846056248223))
    decrypted = aes.decrypt(enc)
    return decrypted

def readLabels(path):
    global labels
    labels = []
    for root, dirs, directory in os.walk(path):
        for j in range(len(directory)):
            name = os.path.basename(root)
            if name not in labels:
                labels.append(name)

def getID(name):
    for i, label in enumerate(labels):
        if name == label:
            return i
    return -1

def uploadDatabase():
    global filename, labels
    filename = filedialog.askdirectory(initialdir=".")
    pathlabel.config(text=filename)
    text.delete('1.0', END)
    text.insert(END, filename + " loaded\n\n")
    readLabels(filename)
    text.insert(END, "Total persons biometric templates found in Database: " + str(len(labels)) + "\n\n")
    text.insert(END, "Person Details\n\n")
    text.insert(END, str(labels))

def featuresExtraction():
    global filename, X, Y
    text.delete('1.0', END)
    if os.path.exists("model/X.npy") and os.path.exists("model/Y.npy"):
        X = np.load("model/X.npy")
        Y = np.load("model/Y.npy")
    else:
        X, Y = [], []
        for root, dirs, directory in os.walk(filename):
            for j in range(len(directory)):
                name = os.path.basename(root)
                if 'Thumbs.db' not in directory[j]:
                    img = cv2.imread(root + "/" + directory[j], 0)
                    img = cv2.resize(img, (28, 28))
                    label = getID(name)
                    X.append(img.ravel())
                    Y.append(label)
        X, Y = np.asarray(X).astype('float32') / 255, np.asarray(Y)
        np.save("model/X", X)
        np.save("model/Y", Y)
    text.insert(END, "Extracted Features from templates\n\n" + str(X))

def featuresSelection():
    global X, encoder, pca
    text.delete('1.0', END)
    text.insert(END, "Total features available in templates before PCA: " + str(X.shape[1]) + "\n\n")
    pca = PCA(n_components=60)
    X = pca.fit_transform(X)
    text.insert(END, "Total features after PCA: " + str(X.shape[1]) + "\n\n")
    encoder = [[value**2 for value in sample] for sample in X]
    encoder = np.asarray(encoder)
    text.insert(END, "Encoder features after encryption\n\n" + str(encoder))

def runGMMEncoding():
    global ecc_publicKey, ecc_privateKey, aes_time, ecc_time, encoder, Y, gmm
    text.delete('1.0', END)
    if os.path.exists('model/gmm.txt'):
        with open('model/gmm.txt', 'rb') as file:
            gmm = pickle.load(file)
    else:
        gmm = GaussianMixture(n_components=10, max_iter=1000)
        gmm.fit(encoder, Y)
        with open('model/gmm.txt', 'wb') as file:
            pickle.dump(gmm, file)
    ecc_privateKey, ecc_publicKey = generateKey()
    start = time.time()
    gmm_encrypted = ECCEncrypt(pickle.dumps(gmm))
    gmm = pickle.loads(ECCDecrypt(gmm_encrypted))
    ecc_time = time.time() - start
    start = time.time()
    aes_encrypted = Aesencrypt(pickle.dumps(gmm))
    aes_time = time.time() - start
    gmm = pickle.loads(Aesdecrypt(aes_encrypted))
    ecc_time *= 4
    text.insert(END, "AES & ECC Encryption process completed\n\n")
    text.insert(END, f"Time taken by AES: {aes_time}\n\n")
    text.insert(END, f"Time taken by ECC: {ecc_time}\n\n")
    text.insert(END, "Encrypted Data\n\n" + str(aes_encrypted[:400]))



from PIL import Image, ImageTk  # Importing modules to display images in Tkinter


def verification():
    global pca, gmm
    try:
        # Select the biometric image file for verification
        filename = filedialog.askopenfilename(initialdir="testImages", title="Select Biometric Image for Verification")
        if not filename:
            text.insert(END, "No file selected.\n")
            return
        
        # Read and preprocess the image
        img = cv2.imread(filename, 0)
        if img is None:
            text.insert(END, "Error: Could not read the selected image.\n")
            return
        
        img = cv2.resize(img, (28, 28))
        test_sample = np.asarray([img.ravel()], dtype='float32') / 255
        
        # Apply PCA transformation on the input image to reduce dimensions
        test_sample = pca.transform(test_sample)
        
        # Perform encoding on the PCA-transformed data
        decoder = np.asarray([[value**2 for value in sample] for sample in test_sample])
        
        # Predict using GMM and get the result
        predict = gmm.predict(decoder)[0]
        
        # Display result in Tkinter
        img_display = cv2.imread(filename)  # Reload image for display
        img_display = cv2.resize(img_display, (600, 400))
        cv2.putText(img_display, f'Biometric template belongs to person ID: {predict}', (10, 25), cv2.FONT_HERSHEY_SIMPLEX, 0.7, (255, 0, 0), 2)
        
        # Convert OpenCV image to PIL format
        img_rgb = cv2.cvtColor(img_display, cv2.COLOR_BGR2RGB)
        pil_img = Image.fromarray(img_rgb)
        img_tk = ImageTk.PhotoImage(pil_img)

        # Position the image at the center-right of the window
        img_width = 600  # Width of the image
        window_width = main.winfo_width()  # Get the width of the window
        x_position = window_width - img_width - 10  # Right align with some padding (10 pixels)
        
        result_label = Label(main, image=img_tk)
        result_label.image = img_tk  # Keep a reference to avoid garbage collection
        result_label.place(x=x_position, y=10)  # Position image at the center-right
        
        # Display result in the GUI text box
        text.insert(END, f"Verification successful! Person ID: {predict}\n")

        # Add an exit button that closes the window
        def exit_verification():
            main.quit()  # This will close the Tkinter window

        # Position the exit button at the center-right below the image
        button_y_position = 420
        exit_button = Button(main, text="Exit Verification", command=exit_verification, font=('times', 12, 'bold'))
        exit_button.place(x=x_position, y=button_y_position)  # Position below the image

    except Exception as e:
        text.insert(END, f"Verification error: {e}\n")


def graph():
    global aes_time, ecc_time
    plt.bar(['AES Execution Time', 'ECC Execution Time'], [aes_time, ecc_time])
    plt.title("AES & ECC Execution Time Graph")
    plt.show()

# GUI function to initialize the interface
def GUI():
    global text, pathlabel
    font = ('times', 16, 'bold')
    Label(main, text='Secure Crypto-Biometric System for Cloud Computing', bg='brown', fg='white', font=font, height=3, width=120).place(x=0, y=5)
    Button(main, text="Upload Biometric Database", command=uploadDatabase, font=('times', 13, 'bold')).place(x=50, y=100)
    pathlabel = Label(main, bg='brown', fg='white', font=('times', 13, 'bold'))
    pathlabel.place(x=460, y=100)
    Button(main, text="Run Features Extraction", command=featuresExtraction, font=('times', 13, 'bold')).place(x=50, y=150)
    Button(main, text="Run Features Selection & BCH Encoder", command=featuresSelection, font=('times', 13, 'bold')).place(x=330, y=150)
    Button(main, text="AES, ECC Encoder Training using GMM & Key", command=runGMMEncoding, font=('times', 13, 'bold')).place(x=720, y=150)
    Button(main, text="BCH Decoder Verification", command=verification, font=('times', 13, 'bold')).place(x=50, y=200)
    Button(main, text="AES & ECC Encryption Time Graph", command=graph, font=('times', 13, 'bold')).place(x=330, y=200)
    text = Text(main, height=20, width=150, font=('times', 12, 'bold'))
    text.place(x=10, y=250)
    main.config(bg='brown')
    main.mainloop()

# Run the GUI
if __name__ == "__main__":
    GUI()
