/**
 * AntiGravity - Blockchain Certificate Validation System
 * Core Application Logic (SPA)
 */

// ==========================================
// MOCK DATA & STORAGE WRAPPER
// ==========================================

const Storage = {
    get: (key) => JSON.parse(localStorage.getItem(`cert_${key}`) || 'null'),
    set: (key, val) => localStorage.setItem(`cert_${key}`, JSON.stringify(val)),

    // Initialize default data if empty
    init: () => {
        if (!Storage.get('users')) {
            Storage.set('users', [
                { id: 'admin', name: 'System Admin', email: 'admin@sys.com', role: 'ADMIN', password: 'admin' },
                { id: 'user1', name: 'John Doe', email: 'john@example.com', role: 'USER', password: 'user' },
                { id: 'verifier1', name: 'Acme Corp', email: 'hr@acme.com', role: 'VERIFIER', password: 'ver' }
            ]);
        }
        if (!Storage.get('certificates')) {
            Storage.set('certificates', []);
        }
        if (!Storage.get('institutions')) {
            Storage.set('institutions', [
                { id: 'inst1', name: 'MIT', email: 'records@mit.edu' },
                { id: 'inst2', name: 'Stanford', email: 'verify@stanford.edu' }
            ]);
        }
    }
};

Storage.init();

// ==========================================
// MOCK API SERVICES
// ==========================================

// ==========================================
// CONFIGURATION & BLOCKCHAIN SERVICES
// ==========================================

const CONFIG = {
    // START: USER MUST UPDATE THESE
    CONTRACT_ADDRESS: "0xc530D241c6F1Efd3305a256C95a9e8ee83e2a352",
    PINATA_API_KEY: "YOUR_PINATA_KEY",
    PINATA_SECRET_KEY: "YOUR_PINATA_SECRET",
    // END
    SEPOLIA_CHAIN_ID: '0xaa36a7', // 11155111
    ALCHEMY_RPC: "https://eth-sepolia.g.alchemy.com/v2/jYiPgY_F3eTXH5Nrrie56"

};

const CONTRACT_ABI = [
    "function addCertificate(string _certificateId, string _ipfsHash, string _issuerName) public",
    "function verifyCertificate(string _certificateId) public view returns (string ipfsHash, string issuerName, address issuerAddress, uint256 issuedAt, bool exists)"
];
// READ-ONLY PROVIDER (for Public & Verifier access)
const READ_ONLY_PROVIDER = new ethers.providers.JsonRpcProvider(
    CONFIG.ALCHEMY_RPC
);


const Wallet = {
    provider: null,
    signer: null,
    address: null,
    isConnected: false,

    connect: async () => {
        if (!window.ethereum) {
            alert("MetaMask not found! Please install.");
            return;
        }

        try {
            await window.ethereum.request({ method: 'eth_requestAccounts' });
            const provider = new ethers.providers.Web3Provider(window.ethereum);
            const { chainId } = await provider.getNetwork();

            if (chainId !== 11155111) {
                alert("Incorrect Network! Please switch to Sepolia.");
                try {
                    await window.ethereum.request({
                        method: 'wallet_switchEthereumChain',
                        params: [{ chainId: CONFIG.SEPOLIA_CHAIN_ID }],
                    });
                } catch (switchError) {
                    throw new Error("Please switch to Sepolia Network manually.");
                }
            }

            const signer = provider.getSigner();
            const address = await signer.getAddress();

            Wallet.provider = provider;
            Wallet.signer = signer;
            Wallet.address = address;
            Wallet.isConnected = true;

            console.log("Wallet Connected:", address);

            // UI Feedback
            const btn = document.getElementById('wallet-btn');
            if (btn) {
                btn.innerHTML = `<i class='bx bxs-wallet'></i> ${address.substring(0, 6)}...${address.substring(38)}`;
                btn.classList.add('btn-primary');
                btn.classList.remove('btn-secondary');
            }
            // alert("Wallet Connected Successfully!"); // Optional: overly intrusive if UI updates
            return address;
        } catch (err) {
            console.error(err);
            alert("Wallet Connection Failed: " + (err.message || err));
            throw new Error(err.message || "Wallet connection failed");
        }
    }
};

const Blockchain = {
    getContract: (withSigner = false) => {
        if (!CONFIG.CONTRACT_ADDRESS || CONFIG.CONTRACT_ADDRESS.includes("0x0000")) {
            throw new Error("Contract Address not set! Please deploy contract and update CONFIG in app.js");
        }
        const provider = withSigner
            ? Wallet.signer
            : READ_ONLY_PROVIDER;

        return new ethers.Contract(CONFIG.CONTRACT_ADDRESS, CONTRACT_ABI, provider);
    },

    writeCertificate: async (id, hash, issuerName) => {
        try {
            if (!Wallet.isConnected) await Wallet.connect();
            const contract = Blockchain.getContract(true);
            const tx = await contract.addCertificate(id, hash, issuerName);
            return tx;
        } catch (err) {
            console.error("Blockchain Write Error:", err);
            throw err;
        }
    },

    verifyCertificate: async (id) => {
        try {
            // Attempt to use wallet provider if connected, else public.
            // Note: Public RPCs might fail due to rate limits/CORS in browser. 
            // Fallback: Propagate error to UI to ask user to connect wallet if read fails.
            const contract = Blockchain.getContract(false);
            const data = await contract.verifyCertificate(id);
            if (!data.exists) return null;
            return {
                ipfsHash: data.ipfsHash,
                issuerName: data.issuerName,
                issuerAddress: data.issuerAddress,
                issuedAt: new Date(data.issuedAt.toNumber() * 1000).toLocaleString(),
                exists: data.exists
            };
        } catch (err) {
            console.error("Verification Error:", err);
            throw err;
        }
    }
};

const IPFS = {
    upload: async (jsonData) => {
        // Use Mock if keys missing (Graceful Demo Fallback)
        if (CONFIG.PINATA_API_KEY.includes("YOUR_")) {
            console.warn("Using MOCK IPFS (No API Keys provided)");
            await new Promise(r => setTimeout(r, 1000));
            return "Qm" + Math.random().toString(36).substr(2, 10) + "MockHash";
        }

        const url = `https://api.pinata.cloud/pinning/pinJSONToIPFS`;
        try {
            const response = await fetch(url, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'pinata_api_key': CONFIG.PINATA_API_KEY,
                    'pinata_secret_api_key': CONFIG.PINATA_SECRET_KEY
                },
                body: JSON.stringify(jsonData)
            });
            const result = await response.json();
            if (result.error) throw new Error(result.error);
            return result.IpfsHash;
        } catch (err) {
            console.error("IPFS Upload Failed", err);
            throw new Error("IPFS Upload Failed: " + err.message);
        }
    }
};

// Kept Auth API
const API = {
    delay: (ms) => new Promise(resolve => setTimeout(resolve, ms)),
    login: async (email, password) => {
        await new Promise(resolve => setTimeout(resolve, 800));
        const users = Storage.get('users');
        const user = users.find(u => u.email === email && u.password === password);
        return user || null;
    },
    register: async (userData) => {
        await new Promise(resolve => setTimeout(resolve, 1000));
        const users = Storage.get('users');
        if (users.find(u => u.email === userData.email)) throw new Error("User already exists");
        const newUser = { ...userData, id: 'user_' + Date.now() };
        users.push(newUser);
        Storage.set('users', users);
        return newUser;
    },
    ocrExtract: async (file) => {
        console.log(`[OCR] Analyzing file: ${file.name}`);
        await new Promise(resolve => setTimeout(resolve, 2000));
        return {
            name: "John Doe",
            registerNumber: "CS2025" + Math.floor(Math.random() * 9000),
            institution: "MIT",
            degree: "B.Sc Computer Science",
            year: "2024",
            gpa: "3.8"
        };
    }
};


// ==========================================
// STATE MANAGEMENT & ROUTER
// ==========================================

const State = {
    user: null, // Current logged in user
    currentPage: 'login',
    notifications: [],

    // Actions
    navigate: (page) => {
        State.currentPage = page;
        Render.app();
    },

    loginUser: (user) => {
        State.user = user;
        // Redirect based on role
        if (user.role === 'ADMIN') State.navigate('admin-dashboard');
        else if (user.role === 'USER') State.navigate('user-dashboard');
        else if (user.role === 'VERIFIER') State.navigate('verifier-dashboard');
    },

    logout: () => {
        State.user = null;
        State.navigate('login');
    }
};

// ==========================================
// COMPONENT RENDERERS
// ==========================================

const Views = {
    login: () => `
        <div class="login-container">
            <div class="glass-card login-card animate-fade">
                <div style="text-align: center; margin-bottom: 2rem;">
                    <i class='bx bxs-cube-alt' style="font-size: 3rem; color: var(--primary);"></i>
                    <h2 class="mt-4">CertValid</h2>
                    <p style="color: var(--text-muted)">Secure Certificate Verification System</p>
                </div>
                
                <form onsubmit="Handlers.handleLogin(event)">
                    <div class="input-group">
                        <label class="input-label">Email Address</label>
                        <input type="email" name="email" class="input-field" placeholder="admin@sys.com" required>
                    </div>
                    <div class="input-group">
                        <label class="input-label">Password</label>
                        <input type="password" name="password" class="input-field" placeholder="••••••" required>
                    </div>
                    
                    <button type="submit" class="btn btn-primary w-full justify-center">
                        Secure Login <i class='bx bx-log-in-circle'></i>
                    </button>
                    
                    <div class="mt-4" style="text-align: center; font-size: 0.9rem;">
                        <span style="color: var(--text-muted)">New User?</span> 
                        <a href="#" onclick="State.navigate('register')" style="color: var(--primary-light)">Create Account</a>
                    </div>
                     <div class="mt-4" style="text-align: center;">
                        <a href="#" onclick="State.navigate('public-verify')" style="color: var(--text-muted); text-decoration: underline;">Public Verification Portal</a>
                    </div>
                </form>

                <!-- Helper for Demo -->
                <div style="margin-top: 2rem; padding-top: 1rem; border-top: 1px solid var(--glass-border); font-size: 0.8rem; color: var(--text-muted);">
                    <p><strong>Demo Credentials:</strong></p>
                    <div class="flex justify-between mt-2">
                        <span>Admin: admin@sys.com / admin</span>
                    </div>
                     <div class="flex justify-between">
                        <span>User: john@example.com / user</span>
                    </div>
                     <div class="flex justify-between">
                        <span>Verifier: hr@acme.com / ver</span>
                    </div>
                </div>
            </div>
        </div>
    `,

    register: () => `
        <div class="login-container">
            <div class="glass-card login-card animate-fade">
                <h2 style="margin-bottom: 1.5rem;">Create Account</h2>
                <form onsubmit="Handlers.handleRegister(event)">
                    <div class="input-group">
                        <label class="input-label">Full Name</label>
                        <input type="text" name="name" class="input-field" required>
                    </div>
                    <div class="input-group">
                        <label class="input-label">Email</label>
                        <input type="email" name="email" class="input-field" required>
                    </div>
                     <div class="input-group">
                        <label class="input-label">Role</label>
                        <select name="role" class="input-field">
                            <option value="USER">Student / Graduate</option>
                            <option value="VERIFIER">Employer / Organization</option>
                        </select>
                    </div>
                    <div class="input-group">
                        <label class="input-label">Password</label>
                        <input type="password" name="password" class="input-field" required>
                    </div>
                    
                    <button type="submit" class="btn btn-primary w-full justify-center">
                        Register
                    </button>
                    
                    <div class="mt-4" style="text-align: center;">
                        <a href="#" onclick="State.navigate('login')" style="color: var(--text-muted)">Back to Login</a>
                    </div>
                </form>
            </div>
        </div>
    `,

    // LAYOUT WRAPPER FOR DASHBOARDS
    dashboardLayout: (content, activeNav) => `
        <div class="dashboard-grid">
            <aside class="sidebar">
                <div class="flex items-center gap-4 mb-4" style="padding-bottom: 2rem; border-bottom: 1px solid var(--glass-border);">
                    <i class='bx bxs-cube-alt' style="font-size: 2rem; color: var(--primary);"></i>
                    <div>
                        <h3 style="font-size: 1.2rem;">CertValid</h3>
                        <span style="font-size: 0.8rem; color: var(--text-muted);">${State.user?.role} VIEW</span>
                    </div>
                </div>

                <nav>
                    ${State.user?.role === 'ADMIN' ? `
                        <a href="#" onclick="State.navigate('admin-dashboard')" class="nav-item ${activeNav === 'overview' ? 'active' : ''}">
                            <i class='bx bxs-dashboard'></i> Overview
                        </a>
                        <a href="#" onclick="State.navigate('admin-users')" class="nav-item ${activeNav === 'users' ? 'active' : ''}">
                            <i class='bx bxs-user-account'></i> User Mgmt.
                        </a>
                    ` : ''}

                    ${State.user?.role === 'USER' ? `
                        <a href="#" onclick="State.navigate('user-dashboard')" class="nav-item ${activeNav === 'upload' ? 'active' : ''}">
                            <i class='bx bxs-cloud-upload'></i> Upload Cert
                        </a>
                        <a href="#" onclick="State.navigate('user-history')" class="nav-item ${activeNav === 'history' ? 'active' : ''}">
                            <i class='bx bx-history'></i> My Certificates
                        </a>
                    ` : ''}

                    ${State.user?.role === 'VERIFIER' ? `
                         <a href="#" onclick="State.navigate('verifier-dashboard')" class="nav-item ${activeNav === 'search' ? 'active' : ''}">
                            <i class='bx bx-search-alt'></i> Verify Certificate
                        </a>
                    ` : ''}

                    <div style="margin-top: 2rem; padding-top: 1rem; border-top: 1px solid var(--glass-border);">
                         <a href="#" onclick="State.logout()" class="nav-item">
                            <i class='bx bx-log-out'></i> Logout
                        </a>
                    </div>
                </nav>
            </aside>
            <main class="main-content">
                <header class="flex justify-between items-center mb-4">
                    <h2 class="animate-fade">Dashboard</h2>
                    <div class="flex items-center gap-4">
                        <button onclick="Wallet.connect()" id="wallet-btn" class="btn btn-secondary" style="padding: 6px 12px; font-size: 0.8rem;">
                            <i class='bx bx-wallet'></i> Connect Wallet
                        </button>
                        <span style="color: var(--text-muted)">Welcome, ${State.user?.name || 'Guest'}</span>
                        <div style="width: 40px; height: 40px; background: var(--primary); border-radius: 50%; display: flex; align-items: center; justify-content: center; font-weight: bold;">
                            ${State.user?.name ? State.user.name.charAt(0) : 'G'}
                        </div>
                    </div>
                </header>
                <div class="animate-fade">
                    ${content}
                </div>
            </main>
        </div>
    `
};

// ==========================================
// EVENT HANDLERS
// ==========================================

const Handlers = {
    handleLogin: async (e) => {
        e.preventDefault();
        const form = new FormData(e.target);
        const email = form.get('email');
        const pass = form.get('password');

        try {
            const user = await API.login(email, pass);
            if (user) {
                State.loginUser(user);
            } else {
                alert('Invalid credentials');
            }
        } catch (err) {
            console.error(err);
        }
    },

    handleRegister: async (e) => {
        e.preventDefault();
        const form = new FormData(e.target);
        const data = Object.fromEntries(form.entries());
        try {
            await API.register(data);
            alert('Registration Successful! Please Login.');
            State.navigate('login');
        } catch (err) {
            alert(err.message);
        }
    }
};

// ==========================================
// MAIN RENDER FUNCTION
// ==========================================

const Render = {
    app: () => {
        const app = document.getElementById('app');

        switch (State.currentPage) {
            case 'login':
                app.innerHTML = Views.login();
                break;
            case 'register':
                app.innerHTML = Views.register();
                break;



            // USER ROUTES
            case 'user-dashboard':
                app.innerHTML = Views.dashboardLayout(Views.userUpload(), 'upload');
                break;
            case 'user-history':
                app.innerHTML = Views.dashboardLayout(Views.userHistory(), 'history');
                break;

            // VERIFIER ROUTES
            case 'verifier-dashboard':
                app.innerHTML = Views.dashboardLayout(Views.verifierSearch(), 'search');
                break;

            // ADMIN ROUTES
            case 'admin-dashboard':
                app.innerHTML = Views.dashboardLayout(Views.adminOverview(), 'overview');
                break;
            case 'admin-users':
                app.innerHTML = Views.dashboardLayout(Views.adminUsers(), 'users');
                break;

            // PUBLIC ROUTE
            case 'public-verify':
                app.innerHTML = `
                    <div class="container" style="padding-top: 4rem;">
                        <header class="flex justify-between items-center mb-4">
                            <div class="flex items-center gap-4">
                                <i class='bx bxs-cube-alt' style="font-size: 2rem; color: var(--primary);"></i>
                                <h2>CertValid Public</h2>
                            </div>
                            <button onclick="State.navigate('login')" class="btn btn-secondary">Login</button>
                        </header>
                        ${Views.verifierSearch()}
                    </div>
                 `;
                break;

            default:
                app.innerHTML = '<h1>404 Page Not Found</h1>';
        }
    }
}

// ==========================================
// ADDITIONAL COMPONENT VIEWS (USER)
// ==========================================

Views.userUpload = () => `
    <div class="glass-card" style="max-width: 800px; margin: 0 auto;">
        <h3>Upload Certificate</h3>
        <p class="mb-4" style="color: var(--text-muted)">Upload your degree/certificate to start the verification process.</p>
        
        <div id="upload-step-1">
            <div class="file-upload-zone" onclick="document.getElementById('fileInput').click()">
                <i class='bx bxs-cloud-upload' style="font-size: 3rem; color: var(--primary);"></i>
                <h4 class="mt-4">Click to Upload or Drag File</h4>
                <p style="color: var(--text-muted)">Supports PNG, JPG, PDF (Max 5MB)</p>
                <input type="file" id="fileInput" hidden onchange="Handlers.handleFileUpload(this)">
            </div>
        </div>

        <div id="upload-step-2" class="hidden mt-8">
            <div class="flex items-center gap-4 mb-4">
                <div class="loader" style="width: 24px; height: 24px;"></div>
                <span>Analyzing Certificate with OCR AI...</span>
            </div>
        </div>

        <div id="upload-step-3" class="hidden mt-8">
            <div style="background: rgba(15, 23, 42, 0.5); padding: 1.5rem; border-radius: var(--radius-sm); border: 1px solid var(--glass-border);">
                <h4 style="margin-bottom: 1rem; color: var(--primary-light)">Extracted Details</h4>
                <div class="grid" style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem;">
                    <div>
                        <label class="input-label">Student Name</label>
                        <input type="text" id="ocr-name" class="input-field" readonly>
                    </div>
                    <div>
                        <label class="input-label">Register Number</label>
                        <input type="text" id="ocr-reg" class="input-field" readonly>
                    </div>
                    <div>
                        <label class="input-label">Institution</label>
                        <input type="text" id="ocr-inst" class="input-field" readonly>
                    </div>
                    <div>
                        <label class="input-label">Degree</label>
                        <input type="text" id="ocr-degree" class="input-field" readonly>
                    </div>
                </div>
                
                <div class="mt-8 flex gap-4">
                    <button class="btn btn-secondary w-full justify-center" onclick="Handlers.resetUpload()">Cancel</button>
                    <button class="btn btn-primary w-full justify-center" onclick="Handlers.submitCertificate()">
                        <i class='bx bx-check-shield'></i> Submit for Verification
                    </button>
                </div>
            </div>
        </div>
    </div>
`;

Views.userHistory = () => {
    const certs = Storage.get('certificates').filter(c => c.userId === State.user.id);

    if (certs.length === 0) return `
        <div class="glass-card" style="text-align: center; padding: 4rem;">
            <i class='bx bx-file-blank' style="font-size: 3rem; color: var(--text-muted);"></i>
            <h3 class="mt-4">No Certificates Uploaded</h3>
            <button class="btn btn-primary mt-4" onclick="State.navigate('user-dashboard')">Upload Now</button>
        </div>
    `;

    return `
        <div class="glass-card">
            <h3>My Certificates</h3>
            <div style="margin-top: 1.5rem;">
                ${certs.map(cert => `
                    <div style="display: flex; align-items: center; justify-content: space-between; padding: 1rem; border-bottom: 1px solid var(--glass-border);">
                        <div>
                            <h4 style="color: var(--primary-light)">${cert.data.degree}</h4>
                            <div style="font-size: 0.9rem; color: var(--text-muted);">
                                ${cert.data.institution} • ${cert.uploadedAt}
                            </div>
                        </div>
                        <div class="flex items-center gap-4">
                            <span class="status-badge ${cert.status === 'VERIFIED' ? 'status-verified' : cert.status === 'PENDING' ? 'status-pending' : 'status-invalid'}">
                                ${cert.status}
                            </span>
                            ${cert.status === 'VERIFIED' ? `
                                <button class="btn btn-secondary" style="padding: 6px 12px; font-size: 0.8rem;" onclick="Handlers.downloadReport('${cert.id}')">
                                    <i class='bx bxs-download'></i> Report
                                </button>
                            ` : ''}
                        </div>
                    </div>
                `).join('')}
            </div>
        </div>
    `;
};

// ==========================================
// ADDITIONAL HANDLERS (USER)
// ==========================================

Handlers.currentOcrData = null;

Handlers.handleFileUpload = async (input) => {
    const file = input.files[0];
    if (!file) return;

    // Show Loader
    document.getElementById('upload-step-1').classList.add('hidden');
    document.getElementById('upload-step-2').classList.remove('hidden');

    try {
        // Stimulate OCR
        const data = await API.ocrExtract(file);
        Handlers.currentOcrData = data;

        // Show Results
        document.getElementById('upload-step-2').classList.add('hidden');
        document.getElementById('upload-step-3').classList.remove('hidden');

        // Fill Form
        document.getElementById('ocr-name').value = data.name;
        document.getElementById('ocr-reg').value = data.registerNumber;
        document.getElementById('ocr-inst').value = data.institution;
        document.getElementById('ocr-degree').value = data.degree;
    } catch (err) {
        alert(err);
        Handlers.resetUpload();
    }
};

Handlers.resetUpload = () => {
    State.navigate('user-dashboard'); // Reloads view
};


Handlers.submitCertificate = async () => {
    if (!Handlers.currentOcrData) return;
    const btn = event.target;
    const originalText = btn.innerHTML;
    btn.innerHTML = `<div class="loader" style="width: 16px; height: 16px; border-width: 2px;"></div> Uploading IPFS...`;

    try {
        // 1. IPFS Upload
        const ipfsHash = await IPFS.upload(Handlers.currentOcrData);

        // 2. Create Record (Pending Blockchain Write by Admin)
        const newCert = {
            id: 'CERT-' + Math.random().toString(36).substr(2, 6).toUpperCase(),
            userId: State.user.id,
            data: Handlers.currentOcrData,
            ipfsHash: ipfsHash,
            status: 'PENDING',
            uploadedAt: new Date().toLocaleDateString(),
            verificationLog: []
        };

        // 3. Save
        const certs = Storage.get('certificates');
        certs.push(newCert);
        Storage.set('certificates', certs);

        alert('Certificate Uploaded to IPFS! Sent to Admin for Blockchain Verification.');
        State.navigate('user-history');

    } catch (err) {
        alert("Submission Failed: " + err.message);
        btn.innerHTML = originalText;
    }
};

Handlers.downloadReport = (id) => {
    const cert = Storage.get('certificates').find(c => c.id === id);
    const content = `VERIFICATION REPORT\n\nID: ${cert.id}\nStatus: ${cert.status}\nBlockchain Hash: ${cert.txHash}\nIPFS: ${cert.ipfsHash}`;

    const blob = new Blob([content], { type: 'text/plain' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `report-${cert.id}.txt`;
    a.click();
};

// ==========================================
// ADDITIONAL COMPONENT VIEWS (VERIFIER & ADMIN)
// ==========================================

Views.adminUsers = () => {
    const users = Storage.get('users');
    return `
        <div class="glass-card">
            <h3>User Management</h3>
            <p style="color: var(--text-muted); font-size: 0.9rem; margin-bottom: 1.5rem;">
                Manage registered users and verified entities.
            </p>
            <table style="width: 100%; text-align: left; border-collapse: collapse;">
                <thead>
                    <tr style="border-bottom: 1px solid var(--glass-border); color: var(--text-muted);">
                        <th style="padding: 1rem;">Name</th>
                        <th style="padding: 1rem;">Email</th>
                        <th style="padding: 1rem;">Role</th>
                        <th style="padding: 1rem;">Status</th>
                    </tr>
                </thead>
                <tbody>
                    ${users.map(u => `
                        <tr style="border-bottom: 1px solid rgba(255,255,255,0.05);">
                            <td style="padding: 1rem;">${u.name}</td>
                            <td style="padding: 1rem;">${u.email}</td>
                            <td style="padding: 1rem;">
                                <span class="status-badge" style="background: rgba(99,102,241,0.15); color: var(--primary-light);">
                                    ${u.role}
                                </span>
                            </td>
                            <td style="padding: 1rem; color: var(--success);">Active</td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        </div>
    `;
};

Views.verifierSearch = () => `
    <div class="glass-card" style="max-width: 800px; margin: 0 auto;">
        <h3>Verify Certificate Authenticity</h3>
        <p class="mb-4" style="color: var(--text-muted)">Enter the Certificate ID or IPFS Hash to verify authenticity on the Blockchain.</p>
        
        <form onsubmit="Handlers.handleVerificationSearch(event)">
            <div class="flex gap-4">
                <input type="text" name="searchQuery" class="input-field" placeholder="e.g. CERT-X7Y2Z9..." required>
                <button type="submit" class="btn btn-primary">Search</button>
            </div>
        </form>

        <div id="verification-result" class="mt-8 hidden">
             <!-- Result injected here -->
        </div>
    </div>
`;

Views.adminOverview = () => {
    const certs = Storage.get('certificates');
    const pending = certs.filter(c => c.status === 'PENDING');
    const verified = certs.filter(c => c.status === 'VERIFIED');

    return `
        <div class="grid" style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 1.5rem; margin-bottom: 2rem;">
             <div class="glass-card">
                <span style="color: var(--text-muted)">Total Certificates</span>
                <h2>${certs.length}</h2>
             </div>
             <div class="glass-card">
                <span style="color: var(--warning)">Pending Approval</span>
                <h2>${pending.length}</h2>
             </div>
             <div class="glass-card">
                <span style="color: var(--success)">Verified On-Chain</span>
                <h2>${verified.length}</h2>
             </div>
        </div>

        <div class="glass-card">
            <h3>Pending Approvals (Institution Simulation)</h3>
            <p style="color: var(--text-muted); font-size: 0.9rem; margin-bottom: 1rem;">
                *In a real system, these would be handled via Email Links by the University. As Admin/Demo, you can override here.
            </p>

            ${pending.length === 0 ? '<p>No pending certificates.</p>' : `
                <table style="width: 100%; text-align: left; border-collapse: collapse;">
                    <thead>
                        <tr style="border-bottom: 1px solid var(--glass-border); color: var(--text-muted);">
                            <th style="padding: 1rem;">ID</th>
                            <th style="padding: 1rem;">Student</th>
                            <th style="padding: 1rem;">Institution</th>
                            <th style="padding: 1rem;">Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${pending.map(c => `
                            <tr style="border-bottom: 1px solid rgba(255,255,255,0.05);">
                                <td style="padding: 1rem;">${c.id}</td>
                                <td style="padding: 1rem;">${c.data.name}</td>
                                <td style="padding: 1rem;">${c.data.institution}</td>
                                <td style="padding: 1rem;">
                                    <div class="flex gap-2">
                                        <button class="btn btn-success" style="padding: 6px; background: rgba(34,197,94,0.2); color: var(--success); border:none; cursor:pointer;" onclick="Handlers.adminVerify('${c.id}', true)">
                                            <i class='bx bxs-check-shield'></i> Write to Blockchain
                                        </button>
                                        <button class="btn btn-danger" style="padding: 6px; background: rgba(239,68,68,0.2); color: var(--danger); border:none; cursor:pointer;" onclick="Handlers.adminVerify('${c.id}', false)">
                                            <i class='bx bx-x'></i> Reject
                                        </button>
                                    </div>
                                </td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            `}
        </div>
    `;
};

// ==========================================
// ADDITIONAL HANDLERS (VERIFIER & ADMIN)
// ==========================================

Handlers.handleVerificationSearch = async (e) => {
    e.preventDefault();
    const query = new FormData(e.target).get('searchQuery').trim();
    const resultDiv = document.getElementById('verification-result');

    resultDiv.innerHTML = `<div class="loader" style="margin: 0 auto;"></div><p style="text-align:center; margin-top:10px;">Querying Smart Contract...</p>`;
    resultDiv.classList.remove('hidden');

    try {
        // 1. Read from Blockchain
        const chainData = await Blockchain.verifyCertificate(query);

        // 2. Read from Local DB for Backup/Details (Optional, but good for display)
        const localCert = Storage.get('certificates').find(c => c.id === query);

        if (!chainData && !localCert) {
            throw new Error("Certificate not found on Blockchain or Local Database.");
        }

        const isVerified = !!chainData && chainData.exists;

        resultDiv.innerHTML = `
            <div style="padding: 2rem; background: ${isVerified ? 'rgba(34,197,94,0.1)' : 'rgba(239,68,68,0.1)'}; border: 1px solid ${isVerified ? 'var(--success)' : 'var(--danger)'}; border-radius: var(--radius-md);">
                <div class="flex items-center gap-4 mb-4">
                    <i class='bx ${isVerified ? 'bxs-badge-check' : 'bxs-x-circle'}' style="font-size: 3rem; color: ${isVerified ? 'var(--success)' : 'var(--danger)'}"></i>
                    <div>
                        <h3>${isVerified ? 'Valid Certificate' : 'Invalid / Pending'}</h3>
                        <p>${isVerified ? 'Authenticity Confirmed via Ethereum Blockchain' : 'Certificate not found on-chain.'}</p>
                    </div>
                </div>
                
                ${isVerified ? `
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-top: 2rem; font-size: 0.95rem;">
                     <div><strong>Issuer Name:</strong> ${chainData.issuerName}</div>
                     <div><strong>Issuer Address:</strong> <span style="font-family:monospace; font-size:0.8rem;">${chainData.issuerAddress}</span></div>
                     <div><strong>Issued At:</strong> ${chainData.issuedAt}</div>
                     <div><strong>IPFS Hash:</strong> <span style="font-family:monospace; font-size:0.8rem;">${chainData.ipfsHash}</span></div>
                     
                     ${localCert ? `
                        <div style="grid-column: span 2; margin-top: 1rem; padding-top: 1rem; border-top: 1px solid var(--glass-border);">
                            <h4 style="margin-bottom:0.5rem;">Student Details (Off-Chain)</h4>
                            <p><strong>Name:</strong> ${localCert.data.name}</p>
                            <p><strong>Degree:</strong> ${localCert.data.degree}</p>
                        </div>
                     ` : ''}
                </div>
                ` : ''}
            </div>
        `;

    } catch (err) {
        resultDiv.innerHTML = `
            <div style="text-align: center; color: var(--danger); padding: 1rem; border: 1px solid var(--danger); border-radius: var(--radius-sm);">
                <i class='bx bxs-error-circle' style="font-size: 2rem;"></i>
                <h4>Verification Failed</h4>
                <p>${err.message}</p>
                <button class="btn btn-secondary mt-2" onclick="Wallet.connect().then(()=>Handlers.handleVerificationSearch(e))">Connect Wallet & Retry</button>
            </div>
        `;
    }
};

Handlers.adminVerify = async (id, approve) => {
    if (!confirm(`Are you sure you want to ${approve ? 'ISSUE ON BLOCKCHAIN' : 'REJECT'}? This incurs gas fees.`)) return;

    if (!approve) {
        // Just Update Local State
        const certs = Storage.get('certificates');
        const index = certs.findIndex(c => c.id === id);
        if (index > -1) {
            certs[index].status = 'INVALID';
            Storage.set('certificates', certs);
            State.navigate('admin-dashboard');
        }
        return;
    }

    // Blockchain Write
    try {
        const certs = Storage.get('certificates');
        const cert = certs.find(c => c.id === id);
        if (!cert) return;

        alert("Please confirm the transaction in MetaMask...");

        // Write to Contract: addCertificate(id, ipfsHash, institutionName)
        const tx = await Blockchain.writeCertificate(cert.id, cert.ipfsHash, cert.data.institution);

        alert(`Transaction Sent! Hash: ${tx.hash}\nWaiting for confirmation...`);
        const receipt = await tx.wait(); // Wait for mining

        // Update Local State
        cert.status = 'VERIFIED';
        cert.txHash = tx.hash;
        cert.issuer = await Wallet.address; // Track who issued it locally

        Storage.set('certificates', certs);

        alert("Certificate Successfully Issued on Blockchain!");
        State.navigate('admin-dashboard');

    } catch (err) {
        alert("Blockchain Error: " + (err.message || err));
    }
};

// Start
State.navigate('login');
