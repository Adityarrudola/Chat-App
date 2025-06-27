# 🔐 Secure Chat App – Streamlit Based Encrypted Messaging

A **real-time chat application** built with **Streamlit**, featuring **end-to-end encryption** using the `cryptography` library. This project demonstrates secure message exchange, lightweight UI, and interactive experience—all in your browser.

---

## 🔗 Live Demo  
🌐 [Try the Live App](https://chat-app-8yrmtmbatye7nw3stg28ll.streamlit.app/)

---

## 🛠️ Built With

- [Streamlit](https://streamlit.io/) – For building the web UI  
- **Python 3**  
- [Pandas](https://pandas.pydata.org/) – For data handling  
- [Cryptography](https://cryptography.io/en/latest/) – For message encryption and decryption  

---

## 📂 Features

- ✅ **Real-time chat simulation** using Streamlit widgets  
- ✅ **AES encryption** of all messages before sending  
- ✅ **Secure message decryption** using symmetric keys  
- ✅ Clean, responsive UI for sender and receiver  
- ✅ Easy-to-use interface – no login required  
- ✅ Works entirely in-browser with no backend needed  

---

## 🔐 How Encryption Works

- The app uses **AES (Advanced Encryption Standard)** with **Fernet symmetric encryption**.  
- Each message is encrypted with a key before being sent.  
- On the receiver side, the message is decrypted using the same key.  
- Prevents eavesdropping or tampering.  

---

## 📁 Folder Structure

```
chat-app/
├── chat_app.py           # Main Streamlit application
├── requirements.txt      # Required dependencies
└── README.md             # This file
```

---

## 🚀 Getting Started (Run Locally)

1. **Clone the Repository**
   ```bash
   git clone https://github.com/Adityarrudola/Chat-App.git
   cd Chat-App
   ```

2. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the App**
   ```bash
   streamlit run chat_app.py
   ```

4. Open your browser at `http://localhost:8501`

---

## 📦 requirements.txt

```txt
streamlit
pandas
cryptography
```

---

## 💡 What I Learned

- Integrating **cryptography** with real-time apps  
- Managing UI interactions using Streamlit  
- Building encrypted applications with no backend  
- Clean modular coding and minimal state handling in Streamlit  


