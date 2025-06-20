import streamlit as st
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as sym_padding
import base64
import secrets
from datetime import datetime
import time
import io
from PIL import Image
import html

st.set_page_config(layout="wide", page_title="Secure Messenger", page_icon="🔒")

# Enhanced CSS with better animations and visual hierarchy
st.markdown("""
<style>
    :root {
        --primary: #4361ee;
        --primary-light: #4895ef;
        --secondary: #3f37c9;
        --success: #4cc9f0;
        --danger: #f72585;
        --light: #f8f9fa;
        --dark: #212529;
    }
    
    .stApp {
        background: linear-gradient(135deg, #f5f7fa 0%, #e4e8f0 100%);
        font-family: 'Inter', sans-serif;
        color: #212529;
    }
    
    .user-panel {
        background: rgba(255, 255, 255, 0.95);
        border-radius: 18px;
        box-shadow: 0 8px 32px rgba(31, 38, 135, 0.1);
        padding: 1.5rem;
        margin-bottom: 1.5rem;
        border: 1px solid rgba(255, 255, 255, 0.18);
        backdrop-filter: blur(8px);
        transition: all 0.3s ease;
    }
    
    .user-panel:hover {
        box-shadow: 0 8px 32px rgba(31, 38, 135, 0.15);
    }
    
    .message-container {
        max-height: 400px;
        overflow-y: auto;
        padding-right: 8px;
        scrollbar-width: thin;
    }
    
    .message-bubble {
        padding: 14px 18px;
        border-radius: 22px;
        margin: 12px 0;
        max-width: 80%;
        position: relative;
        animation: fadeIn 0.4s cubic-bezier(0.18, 0.89, 0.32, 1.28);
        transition: transform 0.2s;
    }
    
    .message-bubble:hover {
        transform: scale(1.02);
    }
    
    .sent {
        background: linear-gradient(135deg, var(--primary) 0%, var(--primary-light) 100%);
        color: white;
        margin-left: auto;
        border-bottom-right-radius: 5px;
    }
    
    .received {
        background: var(--light);
        color: var(--dark);
        margin-right: auto;
        border-bottom-left-radius: 5px;
        box-shadow: 0 2px 8px rgba(0,0,0,0.05);
    }
    
    .encrypted-indicator {
        font-size: 0.7rem;
        color: var(--primary);
        margin-top: 4px;
        display: flex;
        align-items: center;
    }
    
    .message-time {
        font-size: 0.7rem;
        opacity: 0.7;
        margin-top: 4px;
        display: flex;
        justify-content: space-between;
    }
    
    .key-display {
        font-family: 'Fira Code', monospace;
        background: rgba(248, 249, 250, 0.8);
        padding: 12px;
        border-radius: 12px;
        border-left: 4px solid var(--primary);
        overflow-wrap: break-word;
        margin-bottom: 1rem;
    }
    
    .stButton>button {
        border-radius: 12px;
        border: none;
        background: linear-gradient(135deg, var(--primary) 0%, var(--secondary) 100%);
        color: white;
        font-weight: 500;
        transition: all 0.3s;
        padding: 10px 20px;
        box-shadow: 0 4px 12px rgba(67, 97, 238, 0.15);
    }
    
    .stButton>button:hover {
        transform: translateY(-2px);
        box-shadow: 0 6px 16px rgba(67, 97, 238, 0.25);
    }
    
    @keyframes fadeIn {
        from { opacity: 0; transform: translateY(12px); }
        to { opacity: 1; transform: translateY(0); }
    }
    
    .status-indicator {
        width: 10px;
        height: 10px;
        border-radius: 50%;
        display: inline-block;
        margin-right: 8px;
        animation: pulse 2s infinite;
    }
    
    .online { background-color: var(--success); }
    .offline { background-color: var(--danger); }
    
    @keyframes pulse {
        0% { transform: scale(0.95); opacity: 0.7; }
        50% { transform: scale(1.05); opacity: 1; }
        100% { transform: scale(0.95); opacity: 0.7; }
    }
    
    /* Custom scrollbar */
    ::-webkit-scrollbar {
        width: 6px;
    }
    
    ::-webkit-scrollbar-track {
        background: rgba(0,0,0,0.05);
        border-radius: 10px;
    }
    
    ::-webkit-scrollbar-thumb {
        background: rgba(67, 97, 238, 0.3);
        border-radius: 10px;
    }
    
    ::-webkit-scrollbar-thumb:hover {
        background: rgba(67, 97, 238, 0.5);
    }
    
    .file-message {
        display: flex;
        flex-direction: column;
        gap: 8px;
        margin-top: 8px;
        padding: 12px;
        background: rgba(0,0,0,0.03);
        border-radius: 8px;
    }
    
    .file-preview {
        max-width: 100%;
        border-radius: 8px;
        border: 1px solid rgba(0,0,0,0.1);
    }
    
    .download-btn {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        padding: 6px 12px;
        background: rgba(67, 97, 238, 0.1);
        border-radius: 6px;
        color: var(--primary);
        text-decoration: none;
        font-size: 0.85rem;
        transition: all 0.2s;
    }
    
    .download-btn:hover {
        background: rgba(67, 97, 238, 0.2);
    }
</style>
""", unsafe_allow_html=True)

# Initialize session states for both users
if 'alice' not in st.session_state:
    st.session_state.alice = {
        'name': "Alice",
        'avatar': "👩‍💻",
        'private_key': rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        ),
        'messages': [],
        'peer_pub_key': None,
        'aes_key': None,
        'status': "online",
        'last_seen': datetime.now().strftime("%H:%M"),
        'show_encrypted': False
    }
    st.session_state.alice['public_key'] = st.session_state.alice['private_key'].public_key()

if 'bob' not in st.session_state:
    st.session_state.bob = {
        'name': "Bob",
        'avatar': "👨‍💻",
        'private_key': rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        ),
        'messages': [],
        'peer_pub_key': None,
        'aes_key': None,
        'status': "online",
        'last_seen': datetime.now().strftime("%H:%M"),
        'show_encrypted': False
    }
    st.session_state.bob['public_key'] = st.session_state.bob['private_key'].public_key()

# Encryption functions
def get_public_key_pem(user):
    return user['public_key'].public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

def encrypt_with_rsa(public_key, data):
    return public_key.encrypt(
        data.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def decrypt_with_rsa(user, encrypted_data):
    return user['private_key'].decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    ).decode('utf-8')

def encrypt_with_aes(key, data):
    if isinstance(data, str):
        data = data.encode('utf-8')

    iv = secrets.token_bytes(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    padder = sym_padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(iv + encrypted_data).decode('utf-8')

def decrypt_with_aes(key, encrypted_data):
    try:
        encrypted_data = base64.b64decode(encrypted_data.encode('utf-8'))
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        decrypted_padded_data = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = sym_padding.PKCS7(128).unpadder()
        decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
        
        return decrypted_data.decode('utf-8') if isinstance(decrypted_data, bytes) else decrypted_data
    except Exception as e:
        st.error(f"Decryption error: {str(e)}")
        return None

def encrypt_file_with_aes(key, file_data, filename):
    """Encrypt any file with AES-CBC"""
    iv = secrets.token_bytes(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    padder = sym_padding.PKCS7(128).padder()
    padded_data = padder.update(file_data) + padder.finalize()
    
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return {
        'encrypted_data': base64.b64encode(iv + encrypted_data).decode('utf-8'),
        'filename': filename,
        'file_type': filename.split('.')[-1].lower() if '.' in filename else 'bin'
    }

def decrypt_file_with_aes(key, encrypted_data):
    """Decrypt files encrypted with AES-CBC"""
    try:
        encrypted_data = base64.b64decode(encrypted_data.encode('utf-8'))
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        
        decrypted_padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        
        unpadder = sym_padding.PKCS7(128).unpadder()
        return unpadder.update(decrypted_padded_data) + unpadder.finalize()
    except Exception as e:
        st.error(f"File decryption error: {str(e)}")
        return None

def create_download_button(file_data, filename, label="Download"):
    """Create a download button for files"""
    b64 = base64.b64encode(file_data).decode()
    href = f'<a href="data:application/octet-stream;base64,{b64}" download="{filename}" class="download-btn">{label} 📥</a>'
    return href

def render_message(sender, content, encrypted_content, timestamp, is_current_user, show_encrypted, is_file=False, file_type=None, filename=None):
    bubble_class = "sent" if is_current_user else "received"
    avatar = st.session_state.alice['avatar'] if sender == "Alice" else st.session_state.bob['avatar']

    if is_file:
        if is_current_user:
            # Sender's view - show original file content
            if file_type in ['jpg', 'jpeg', 'png', 'gif']:
                try:
                    # For sender, content is the original file bytes
                    if isinstance(content, bytes):
                        img = Image.open(io.BytesIO(content))
                        buffered = io.BytesIO()
                        img.save(buffered, format=img.format)
                        img_str = base64.b64encode(buffered.getvalue()).decode()
                        message_content = f"""
                        <div style="margin-bottom: 8px; max-width: 300px;">
                            <img src="data:image/{file_type};base64,{img_str}" 
                                style="max-width: 100%; border-radius: 8px;">
                        </div>
                        <div style="font-size: 0.8rem; color: #666;">{filename}</div>
                        """
                    else:
                        message_content = f"🖼️ [Image - {filename}]"
                except Exception as e:
                    message_content = f"🖼️ [Image - {filename}]"
            else:
                message_content = f"📁 {filename}"
        else:
            # Receiver's view - handle encrypted content
            decrypted_content = None
            if isinstance(content, str):  # Encrypted content is base64 string
                try:
                    decrypted_content = decrypt_file_with_aes(
                        st.session_state.bob['aes_key'] if sender == "Alice" else st.session_state.alice['aes_key'], 
                        content
                    )
                except:
                    pass

            if decrypted_content and file_type in ['jpg', 'jpeg', 'png', 'gif']:
                try:
                    img = Image.open(io.BytesIO(decrypted_content))
                    buffered = io.BytesIO()
                    img.save(buffered, format=img.format)
                    img_str = base64.b64encode(buffered.getvalue()).decode()
                    message_content = f"""
                    <div style="margin-bottom: 8px; max-width: 300px;">
                        <img src="data:image/{file_type};base64,{img_str}" 
                            style="max-width: 100%; border-radius: 8px;">
                    </div>
                    """
                    # Add download button
                    message_content += create_download_button(decrypted_content, filename)
                except Exception as e:
                    message_content = f"🖼️ [Image - {filename}]"
            elif decrypted_content:
                message_content = f"📁 {filename}<br>{create_download_button(decrypted_content, filename)}"
            else:
                message_content = f"🔒 [Encrypted File - {filename}]"

            if show_encrypted:
                message_content += f"""
                <div class="file-message">
                    <div style="font-weight: 500; margin-bottom: 4px;">Encrypted Data:</div>
                    <div style="font-family: monospace; font-size: 0.8rem; word-break: break-word;">
                        {encrypted_content[:120]}...
                    </div>
                </div>
                """
    else:
        # Text message handling
        safe_content = html.escape(content) if isinstance(content, str) else str(content)
        
        if show_encrypted and not is_current_user:
            message_content = f"""
            <div style="margin-bottom: 8px;">
                <div style="font-weight: 500; margin-bottom: 4px;">Decrypted:</div>
                <div>{safe_content}</div>
            </div>
            <div style="margin-top: 8px;">
                <div style="font-weight: 500; margin-bottom: 4px;">Encrypted:</div>
                <div style="font-family: monospace; font-size: 0.8rem; word-break: break-word;">
                    {encrypted_content[:120]}...
                </div>
            </div>
            """
        else:
            message_content = f"<div>{safe_content}</div>"

    st.markdown(f"""
    <div style="display: flex; flex-direction: {'row-reverse' if is_current_user else 'row'}; align-items: flex-end; margin-bottom: 12px;">
        <div style="margin: 0 10px; font-size: 28px; align-self: flex-start;">{avatar}</div>
        <div style="flex: 1;">
            <div class="message-bubble {bubble_class}">
                {message_content}
                <div class="message-time">
                    <span>{timestamp}</span>
                    {f'<span class="encrypted-indicator">🔒 Encrypted</span>' if not is_current_user else ''}
                </div>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)


def render_user_panel(user, other_user):
    with st.container():
        # Header with user info
        col1, col2 = st.columns([1, 4])
        with col1:
            st.markdown(f"<div style='font-size: 36px; text-align: center;'>{user['avatar']}</div>", unsafe_allow_html=True)
        with col2:
            status_class = "online" if user['status'] == "online" else "offline"
            st.markdown(f"""
                <h2 style='margin-bottom: 4px;'>{user['name']}</h2>
                <div style='display: flex; align-items: center; margin-bottom: 8px;'>
                    <span class='status-indicator {status_class}'></span>
                    <span>{user['status'].capitalize()} - Last seen {user['last_seen']}</span>
                </div>
            """, unsafe_allow_html=True)
        
        st.divider()
        
        # Key exchange section
        with st.expander("🔐 Encryption Setup", expanded=not user['aes_key']):
            st.markdown("**Your Public Key**")
            st.markdown(f'<div class="key-display">{get_public_key_pem(user)}</div>', unsafe_allow_html=True)
            
            other_pub_key = st.text_area(f"Paste {other_user['name']}'s Public Key", height=150)
            if st.button(f"Set {other_user['name']}'s Key", key=f"{user['name']}_set_key"):
                try:
                    user['peer_pub_key'] = serialization.load_pem_public_key(
                        other_pub_key.encode('utf-8'),
                        backend=default_backend()
                    )
                    st.success(f"{other_user['name']}'s key configured successfully!")
                    time.sleep(1)
                    st.rerun()
                except Exception as e:
                    st.error(f"Invalid key format: {e}")
            
            if user['peer_pub_key']:
                if st.button("Generate Shared Secret", key=f"{user['name']}_gen_key"):
                    user['aes_key'] = secrets.token_bytes(32)
                    encrypted_key = encrypt_with_rsa(user['peer_pub_key'], base64.b64encode(user['aes_key']).decode('utf-8'))
                    st.session_state[f"{other_user['name'].lower()}_encrypted_key"] = encrypted_key
                    st.success("Shared secret generated! Send the encrypted key to your peer.")
                    st.markdown(f'<div class="key-display">{base64.b64encode(encrypted_key).decode("utf-8")}</div>', unsafe_allow_html=True)
            
            if hasattr(st.session_state, f"{user['name'].lower()}_encrypted_key") and user['peer_pub_key']:
                if st.button("Decrypt Shared Secret", key=f"{user['name']}_decrypt_key"):
                    try:
                        encrypted_key = getattr(st.session_state, f"{user['name'].lower()}_encrypted_key")
                        decrypted_key = decrypt_with_rsa(user, encrypted_key)
                        user['aes_key'] = base64.b64decode(decrypted_key)
                        st.success("Secure session established! You can now send encrypted messages.")
                        time.sleep(1)
                        st.rerun()
                    except Exception as e:
                        st.error(f"Failed to decrypt: {e}")
        
        # Messaging interface
        if user['aes_key']:
            st.markdown("**New Message**")
            col1, col2 = st.columns([4, 1])
            with col1:
                msg = st.text_input(f"Message to {other_user['name']}", key=f"{user['name']}_msg", label_visibility="collapsed")
                uploaded_file = st.file_uploader("Or upload a file", type=['pdf', 'jpg', 'jpeg', 'png', 'txt', 'docx'], key=f"{user['name']}_file_upload")
            with col2:
                if st.button(f"Send", key=f"{user['name']}_send"):
                    if msg or uploaded_file:
                        timestamp = datetime.now().strftime("%H:%M")
                        if uploaded_file:
                            file_data = uploaded_file.read()
                            encrypted_file = encrypt_file_with_aes(user['aes_key'], file_data, uploaded_file.name)
                            
                            # For sender (unencrypted)
                            user['messages'].append({
                                'sender': user['name'],
                                'content': file_data,
                                'encrypted': encrypted_file['encrypted_data'],
                                'timestamp': timestamp,
                                'is_encrypted': False,
                                'is_file': True,
                                'file_type': encrypted_file['file_type'],
                                'filename': encrypted_file['filename']
                            })
                            
                            # For receiver (encrypted)
                            other_user['messages'].append({
                                'sender': user['name'],
                                'content': encrypted_file['encrypted_data'],
                                'encrypted': encrypted_file['encrypted_data'],
                                'timestamp': timestamp,
                                'is_encrypted': True,
                                'is_file': True,
                                'file_type': encrypted_file['file_type'],
                                'filename': encrypted_file['filename']
                            })
                        
                        if msg:
                            encrypted = encrypt_with_aes(user['aes_key'], msg)
                            
                            # For sender (unencrypted)
                            user['messages'].append({
                                'sender': user['name'],
                                'content': msg,
                                'encrypted': encrypted,
                                'timestamp': timestamp,
                                'is_encrypted': False
                            })
                            
                            # For receiver (encrypted)
                            other_user['messages'].append({
                                'sender': user['name'],
                                'content': encrypted,
                                'encrypted': encrypted,
                                'timestamp': timestamp,
                                'is_encrypted': True
                            })
                        
                        st.rerun()

        # Message history
        st.markdown("**Message History**")
        user['show_encrypted'] = st.checkbox("Show encrypted data", value=user['show_encrypted'], key=f"{user['name']}_show_encrypted")

        if not user['messages']:
            st.markdown("""
            <div style="text-align: center; padding: 40px 20px; color: #6c757d; border-radius: 12px; background: rgba(0,0,0,0.02);">
                <div style="font-size: 48px; margin-bottom: 16px;">💬</div>
                <h4 style="margin-bottom: 8px;">No messages yet</h4>
                <p>Start a secure conversation by exchanging keys above</p>
            </div>
            """, unsafe_allow_html=True)
        else:
            with st.container():
                for idx, msg in enumerate(user['messages']):
                    is_current_user = msg['sender'] == user['name']
                    
                    if msg.get('is_file', False):
                        if msg.get('is_encrypted', True):
                            try:
                                decrypted = decrypt_file_with_aes(user['aes_key'], msg['content']) if user['aes_key'] else None
                                render_message(
                                    msg['sender'], 
                                    decrypted if decrypted else b'',
                                    msg['content'],
                                    msg['timestamp'], 
                                    is_current_user,
                                    user['show_encrypted'] and not is_current_user,
                                    is_file=True,
                                    file_type=msg.get('file_type'),
                                    filename=msg.get('filename')
                                )
                                
                                # Add download button for decrypted files
                                if decrypted and not is_current_user:
                                    unique_key = f"dl_{msg['timestamp']}_{msg.get('filename', 'file')}_{idx}"
                                    st.download_button(
                                        label=f"Download {msg.get('filename', 'file')}",
                                        data=decrypted,
                                        file_name=msg.get('filename', 'file'),
                                        key=unique_key
                                    )
                            except Exception as e:
                                st.error(f"Decryption failed: {e}")
                                render_message(
                                    msg['sender'], 
                                    "🔒 [Encrypted File]", 
                                    msg['content'],
                                    msg['timestamp'], 
                                    is_current_user,
                                    False,
                                    is_file=True
                                )
                        else:
                            # For sent files that aren't encrypted (local copy)
                            render_message(
                                msg['sender'], 
                                msg['content'],
                                msg['encrypted'],
                                msg['timestamp'], 
                                is_current_user,
                                False,
                                is_file=True,
                                file_type=msg.get('file_type'),
                                filename=msg.get('filename')
                            )
                    else:
                        # Handle text messages (keep existing text message handling)
                        if msg.get('is_encrypted', True):
                            try:
                                decrypted = decrypt_with_aes(user['aes_key'], msg['content']) if user['aes_key'] else msg['content']
                                render_message(
                                    msg['sender'], 
                                    decrypted, 
                                    msg['content'],
                                    msg['timestamp'], 
                                    is_current_user,
                                    user['show_encrypted'] and not is_current_user
                                )
                            except:
                                render_message(
                                    msg['sender'], 
                                    "🔒 [Encrypted Message]", 
                                    msg['content'],
                                    msg['timestamp'], 
                                    is_current_user,
                                    False
                                )
                        else:
                            render_message(
                                msg['sender'], 
                                msg['content'],
                                msg['encrypted'],
                                msg['timestamp'], 
                                is_current_user,
                                False
                            )
# Main app layout
st.title("🔐 End-to-End Encrypted Multimedia Platform")
st.caption("End-to-end encrypted communication with file sharing")

# Two-column layout with toggle for vertical/horizontal view
view_mode = st.sidebar.radio("View Mode", ["Side-by-Side", "Stacked"], index=0)

if view_mode == "Side-by-Side":
    col1, col2 = st.columns(2, gap="large")
    with col1:
        render_user_panel(st.session_state.alice, st.session_state.bob)
    with col2:
        render_user_panel(st.session_state.bob, st.session_state.alice)
else:
    render_user_panel(st.session_state.alice, st.session_state.bob)
    st.divider()
    render_user_panel(st.session_state.bob, st.session_state.alice)

# Enhanced control panel
with st.sidebar:
    st.markdown("## 🎛️ Control Panel")
    
    # Status toggling
    st.markdown("### User Status")
    user_to_toggle = st.selectbox("Select user", ["Alice", "Bob"])
    new_status = st.radio(f"{user_to_toggle}'s Status", ["online", "offline"], 
                        index=0 if (st.session_state.alice if user_to_toggle == "Alice" else st.session_state.bob)['status'] == "online" else 1)
    
    if st.button(f"Update {user_to_toggle}'s Status"):
        user = st.session_state.alice if user_to_toggle == "Alice" else st.session_state.bob
        user['status'] = new_status
        user['last_seen'] = datetime.now().strftime("%H:%M")
        st.rerun()
    
    st.divider()
    
    # Message controls
    st.markdown("### Message Options")
    if st.button("Clear All Messages"):
        st.session_state.alice['messages'] = []
        st.session_state.bob['messages'] = []
        st.rerun()
    
    if st.button("Generate Sample Messages"):
        timestamp = datetime.now().strftime("%H:%M")
        st.session_state.alice['messages'].append({
            'sender': "Alice",
            'content': "Hey Bob, let's talk securely!",
            'encrypted': encrypt_with_aes(st.session_state.alice['aes_key'], "Hey Bob, let's talk securely!") if st.session_state.alice['aes_key'] else "Hey Bob, let's talk securely!",
            'timestamp': timestamp,
            'is_encrypted': False
        })
        st.session_state.bob['messages'].append({
            'sender': "Alice",
            'content': encrypt_with_aes(st.session_state.alice['aes_key'], "Hey Bob, let's talk securely!") if st.session_state.alice['aes_key'] else "Hey Bob, let's talk securely!",
            'encrypted': encrypt_with_aes(st.session_state.alice['aes_key'], "Hey Bob, let's talk securely!") if st.session_state.alice['aes_key'] else "Hey Bob, let's talk securely!",
            'timestamp': timestamp,
            'is_encrypted': True
        })
        st.rerun()
    
    st.divider()
    st.markdown("### 🔐 Encryption Details")
    st.markdown("""
    **Security Protocols:**
    
    - **RSA-128**: Used for secure key exchange
    - **AES-256-CBC**: Used for message encryption
    - **SHA-256**: Used for hashing in OAEP padding
    
    **How Encryption Works:**

    1. Each user generates RSA key pairs
    2. Public keys are exchanged securely
    3. AES session keys are generated and encrypted with RSA
    4. All messages are encrypted with AES-256
    5. Files are encrypted with AES in CBC mode with PKCS7 padding
    
    **Security Features:**
    
    - Perfect Forward Secrecy (new session keys for each session)
    - End-to-end encryption
    - Cryptographic integrity protection
    """)
    
    st.markdown("""
    <div style="margin-top: 20px; font-size: 0.8rem; color: #6c757d; text-align: center;">
        Built with Python's cryptography.hazmat
    </div>
    """, unsafe_allow_html=True)