# app.py
import streamlit as st
import hashlib, secrets, rsa, base64, time, matplotlib.pyplot as plt
from io import BytesIO

st.set_page_config(page_title="Applied Cryptography Simulator", page_icon="🔐", layout="wide")
st.title("🔐 Applied Cryptography Simulator — Keys, Crypto, ZKP & Attacks")
st.markdown("Interactive simulator covering RSA key mgmt, encryption, signatures, Zero-Knowledge Proofs, and attack demos.")

# Initialize session state containers
if "initialized" not in st.session_state:
    st.session_state.update({
        "initialized": True,
        "pub_a": None, "priv_a": None,
        "pub_b": None, "priv_b": None,
        "pub_ca": None, "priv_ca": None,
        "cipher": None, "sig": None, "hash": None, "msg": None,
        "zkp": {}
    })

tabs = st.tabs(["🔐 Key Management", "🔑 Key Generation", "💬 Communication", "🧾 Signatures",
                "🧠 ZKP Visualizer", "⚠️ Attack Simulation"])

# ------------------ Tab: Key Management ------------------ #
with tabs[0]:
    st.subheader("🔐 Key Management Visualization & Simple CA")
    st.markdown("""
    This tab visualizes **how public keys are distributed and verified**.
    - We create a simple Certificate Authority (CA) that signs public keys (a certificate).
    - Alice and Bob exchange certificates — Bob verifies Alice's certificate using CA's public key.
    - This demonstrates the concept of **certification and trust chains** used in real systems.
    """)
    col1, col2 = st.columns([2, 1])

    with col1:
        st.markdown("**1) CA (Certificate Authority) Setup**")
        if st.button("Generate CA Key Pair (Create CA)"):
            pub_ca, priv_ca = rsa.newkeys(1024)
            st.session_state.pub_ca, st.session_state.priv_ca = pub_ca, priv_ca
            st.success("✅ CA keypair generated.")
            st.code(f"CA Public Key (short): n={pub_ca.n}\ne={pub_ca.e}")

        st.markdown("**2) Create/Issue Certificates for Alice & Bob**")
        c1, c2 = st.columns(2)
        with c1:
            if st.button("Generate Alice Keys & Certificate"):
                pub_a, priv_a = rsa.newkeys(512)
                st.session_state.pub_a, st.session_state.priv_a = pub_a, priv_a
                # Create a simple certificate structure (not X.509 — illustrative)
                cert_a = {
                    "subject": "Alice",
                    "pub_n": pub_a.n,
                    "pub_e": pub_a.e,
                    "issued_by": "Simple-CA"
                }
                cert_bytes = f"{cert_a}".encode()
                # CA signs the certificate bytes
                cert_sig = rsa.sign(cert_bytes, st.session_state.priv_ca, "SHA-256") if st.session_state.priv_ca else None
                st.session_state.cert_a, st.session_state.cert_a_sig = cert_a, cert_sig
                st.success("✅ Alice keys & certificate created.")
                st.code(f"Alice Certificate (preview):\n{cert_a}")

        with c2:
            if st.button("Generate Bob Keys & Certificate"):
                pub_b, priv_b = rsa.newkeys(512)
                st.session_state.pub_b, st.session_state.priv_b = pub_b, priv_b
                cert_b = {
                    "subject": "Bob",
                    "pub_n": pub_b.n,
                    "pub_e": pub_b.e,
                    "issued_by": "Simple-CA"
                }
                cert_bytes = f"{cert_b}".encode()
                cert_sig = rsa.sign(cert_bytes, st.session_state.priv_ca, "SHA-256") if st.session_state.priv_ca else None
                st.session_state.cert_b, st.session_state.cert_b_sig = cert_b, cert_sig
                st.success("✅ Bob keys & certificate created.")
                st.code(f"Bob Certificate (preview):\n{cert_b}")

        st.markdown("**3) Visualize Certificate Exchange & Verification**")
        if st.button("Visualize Exchange & Verify Certificates"):
            # Basic checks
            if not st.session_state.pub_ca:
                st.error("CA keys missing — generate CA first.")
            elif not (st.session_state.cert_a and st.session_state.cert_b):
                st.error("Alice/Bob certificates missing — generate them first.")
            else:
                # Prepare visualization
                fig, ax = plt.subplots(figsize=(8, 2.6))
                ax.set_xlim(0, 10); ax.set_ylim(0, 3); ax.axis("off")
                # Positions
                ca_x, alice_x, bob_x = 1, 4.5, 8.5
                ax.text(ca_x, 2.1, "CA", fontsize=12, color="maroon", weight="bold")
                ax.text(alice_x, 2.1, "Alice", fontsize=12, color="blue", weight="bold")
                ax.text(bob_x, 2.1, "Bob", fontsize=12, color="green", weight="bold")

                # CA issues cert arrow -> Alice
                ax.annotate("", xy=(alice_x - 0.5, 1.8), xytext=(ca_x + 0.8, 1.8),
                            arrowprops=dict(arrowstyle="->", color="orange", lw=2))
                ax.text((ca_x + alice_x) / 2, 1.9, "Cert_A (signed by CA)", ha="center", color="orange")

                # CA issues cert -> Bob
                ax.annotate("", xy=(bob_x - 0.5, 1.5), xytext=(ca_x + 0.8, 1.5),
                            arrowprops=dict(arrowstyle="->", color="orange", lw=2))
                ax.text((ca_x + bob_x) / 2, 1.6, "Cert_B (signed by CA)", ha="center", color="orange")

                # Alice -> Bob (certificate exchange)
                ax.annotate("", xy=(bob_x - 0.5, 1.2), xytext=(alice_x + 0.5, 1.2),
                            arrowprops=dict(arrowstyle="->", color="gray", lw=2))
                ax.text((alice_x + bob_x) / 2, 1.25, "Alice sends certificate to Bob", ha="center")

                st.pyplot(fig)

                # Now actually verify Alice's certificate using CA public key
                try:
                    cert_bytes = f"{st.session_state.cert_a}".encode()
                    rsa.verify(cert_bytes, st.session_state.cert_a_sig, st.session_state.pub_ca)
                    st.success("✅ Bob verified Alice's certificate using CA public key.")
                    st.info("Verification means Bob trusts that the public key in Cert_A belongs to Alice.")
                except Exception as e:
                    st.error("❌ Certificate verification failed (unexpected).")
                    st.exception(e)

    with col2:
        st.markdown("**Quick State Info**")
        if st.session_state.pub_ca:
            st.write("CA public key: ✅ present")
        else:
            st.write("CA public key: ❌ missing")
        st.write("---")
        st.write("Alice key present:", bool(st.session_state.pub_a))
        st.write("Bob key present:", bool(st.session_state.pub_b))
        st.write("---")
        st.write("Alice certificate:", "✅" if st.session_state.get("cert_a") else "❌")
        st.write("Bob certificate:", "✅" if st.session_state.get("cert_b") else "❌")
        st.caption("The 'certificate' here is a small illustrative object (not a real X.509 cert).")

# ------------------ Tab: Key Generation ------------------ #
with tabs[1]:
    st.subheader("🔑 Simple RSA Key Generation (Alice & Bob)")
    c1, c2 = st.columns(2)
    with c1:
        if st.button("Generate Alice RSA Keypair"):
            pub_a, priv_a = rsa.newkeys(512)
            st.session_state.pub_a, st.session_state.priv_a = pub_a, priv_a
            st.success("Alice keys generated.")
            st.code(f"Alice Public Key (n short): {pub_a.n}\n e:{pub_a.e}")
    with c2:
        if st.button("Generate Bob RSA Keypair"):
            pub_b, priv_b = rsa.newkeys(512)
            st.session_state.pub_b, st.session_state.priv_b = pub_b, priv_b
            st.success("Bob keys generated.")
            st.code(f"Bob Public Key (n short): {pub_b.n}\n e:{pub_b.e}")

    st.markdown("You can reuse keys created in the Key Management tab (CA flow) — both tabs share session keys.")

# ------------------ Tab: Communication ------------------ #
with tabs[2]:
    st.subheader("💬 Encrypted Communication (Alice → Bob)")
    if not st.session_state.pub_b:
        st.warning("Generate Bob's keypair first (Key Generation tab).")
    else:
        msg = st.text_input("Message to send (Alice → Bob):", "Hello Bob — secure message.")
        col_a, col_b = st.columns(2)
        with col_a:
            if st.button("Encrypt & Send"):
                cipher = rsa.encrypt(msg.encode(), st.session_state.pub_b)
                st.session_state.cipher = cipher
                st.success("Message encrypted & sent (stored in session).")
                st.code(base64.b64encode(cipher).decode())
        with col_b:
            if st.button("Decrypt (Bob)"):
                try:
                    plain = rsa.decrypt(st.session_state.cipher, st.session_state.priv_b).decode()
                    st.success("Message decrypted at Bob's end:")
                    st.code(plain)
                except Exception as e:
                    st.error("Decryption failed (tampering/keys mismatch).")
                    st.exception(e)

# ------------------ Tab: Signatures ------------------ #
with tabs[3]:
    st.subheader("🧾 Digital Signatures & Hashing")
    text = st.text_area("Message to sign:", "This is an important message.")
    c1, c2 = st.columns(2)
    with c1:
        if st.button("Sign (Alice)"):
            if not st.session_state.priv_a:
                st.error("Alice's private key missing.")
            else:
                h = hashlib.sha256(text.encode()).hexdigest()
                sig = rsa.sign(text.encode(), st.session_state.priv_a, "SHA-256")
                st.session_state.sig, st.session_state.hash, st.session_state.msg = sig, h, text
                st.success("Message signed by Alice.")
                st.code(f"SHA-256 Hash: {h}")
                st.code(f"Signature (base64): {base64.b64encode(sig).decode()}")
    with c2:
        if st.button("Verify (Bob)"):
            if not st.session_state.sig:
                st.error("No signature found — sign a message first.")
            elif not st.session_state.pub_a:
                st.error("Alice's public key missing.")
            else:
                try:
                    rsa.verify(st.session_state.msg.encode(), st.session_state.sig, st.session_state.pub_a)
                    st.success("✅ Signature verified — message is authentic and untampered.")
                except Exception as e:
                    st.error("❌ Signature verification failed.")
                    st.exception(e)

# ------------------ Tab: ZKP Visualizer ------------------ #
with tabs[4]:
    st.subheader("🧠 Zero-Knowledge Proof Visualizer (Interactive)")
    st.markdown("Prover (Alice) proves knowledge of secret `s` to Verifier (Bob) without revealing `s`.\nThis is a simplified interactive number-based ZKP (commit-challenge-response).")

    p = st.number_input("Public prime p", value=23, min_value=5)
    g = st.number_input("Base g", value=5, min_value=2)
    s = st.number_input("Alice's secret s (private)", value=6, min_value=1)
    run_zkp = st.button("Run ZKP (simulate)")

    zkp_out = st.empty()
    if run_zkp:
        # Commitment
        r = secrets.randbelow(p - 1)
        v = pow(g, r, p)
        # Challenge (simulate random bit or small integer)
        e = secrets.randbelow(2)
        y = (r + e * s) % (p - 1)

        # Store for display
        st.session_state.zkp = {"r": r, "v": v, "e": e, "y": y, "p": p, "g": g, "s": s}

        # visual arrows with matplotlib
        fig, ax = plt.subplots(figsize=(7, 2.2))
        ax.set_xlim(0, 7); ax.set_ylim(0, 2.5); ax.axis("off")
        ax.text(1, 2.1, "Alice (Prover)", color="blue", weight="bold")
        ax.text(5.8, 2.1, "Bob (Verifier)", color="green", weight="bold")
        # Commit
        ax.annotate("", xy=(5.2, 1.6), xytext=(1.8, 1.6), arrowprops=dict(arrowstyle="->", color="orange", lw=2))
        ax.text(3.5, 1.7, f"Commit v = g^r mod p = {v}", ha="center", color="orange")
        # Challenge
        ax.annotate("", xy=(1.8, 1.1), xytext=(5.2, 1.1), arrowprops=dict(arrowstyle="->", color="purple", lw=2))
        ax.text(3.5, 1.2, f"Challenge e = {e}", ha="center", color="purple")
        # Response
        ax.annotate("", xy=(5.2, 0.6), xytext=(1.8, 0.6), arrowprops=dict(arrowstyle="->", color="red", lw=2))
        ax.text(3.5, 0.7, f"Response y = {y}", ha="center", color="red")
        st.pyplot(fig)

        # Verify
        lhs = pow(g, y, p)
        rhs = (v * pow(pow(g, s, p), e, p)) % p
        if lhs == rhs:
            zkp_out.success(f"✅ ZKP Verified: LHS={lhs}, RHS={rhs}")
        else:
            zkp_out.error(f"❌ ZKP Failed: LHS={lhs}, RHS={rhs}")

# ------------------ Tab: Attack Simulation ------------------ #
with tabs[5]:
    st.subheader("⚠️ Attack Simulation: Tampering & Forgery")
    st.markdown("Demonstrations showing how tampering or forging fails under correct crypto verification.")

    # Tampered ciphertext demo
    st.markdown("**1) Tampered Ciphertext**")
    if st.button("Run Ciphertext Tamper Demo"):
        if not st.session_state.pub_b or not st.session_state.priv_b:
            st.error("Generate Bob keys first.")
        else:
            msg = "SecretMessage"
            cipher = rsa.encrypt(msg.encode(), st.session_state.pub_b)
            tampered = bytearray(cipher)
            # flip a byte within bounds
            idx = min(10, len(tampered)-1)
            tampered[idx] ^= 0xFF
            try:
                _ = rsa.decrypt(bytes(tampered), st.session_state.priv_b)
                st.error("⚠️ Unexpected: Decryption succeeded on tampered ciphertext.")
            except:
                st.success("✅ Tampering detected: Decryption failed as expected.")

    st.markdown("---")
    # Forged signature demo
    st.markdown("**2) Forged Signature**")
    if st.button("Run Signature Forgery Demo"):
        if not st.session_state.priv_a or not st.session_state.pub_a:
            st.error("Generate Alice keys first.")
        else:
            message = "ImportantDoc"
            valid_sig = rsa.sign(message.encode(), st.session_state.priv_a, "SHA-256")
            forged = bytearray(valid_sig)
            idx = min(5, len(forged)-1)
            forged[idx] ^= 0xAB
            try:
                rsa.verify(message.encode(), bytes(forged), st.session_state.pub_a)
                st.error("⚠️ Unexpected: Forged signature verified.")
            except:
                st.success("✅ Forgery detected: Verification failed as expected.")

st.sidebar.markdown("### ℹ️ Project Summary & Tips")
st.sidebar.info("""
This simulator covers:
- Key generation and small CA-based certificate issuance (illustrative)
- RSA encryption/decryption
- Digital signatures & integrity (SHA-256)
- Zero-Knowledge Proof (commit-challenge-response)
- Attack demos: tampered ciphertext, forged signature

Tips:
- Use the Key Management tab first to create a CA and issue simple certificates.
- Use moderate key sizes here for speed (512/1024) — explain in viva why real systems use 2048+ bits.
""")
