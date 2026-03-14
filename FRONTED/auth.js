/* ═══════════════════════════════════════════
   HORUS — Auth Module (backend + admin users)
   ═══════════════════════════════════════════ */

(function () {
    let API_BASE = window.location.origin;
    if (API_BASE.includes('5500') || API_BASE.includes('file://') || API_BASE === 'null' || window.location.protocol === 'file:') {
        API_BASE = 'http://localhost:3000';
    }
    const API_AUTH = `${API_BASE}/api/auth`;
    const API_ADMIN_USERS = `${API_BASE}/api/admin/users`;

    const SESSION_KEY = 'horus_auth';
    const SESSION_USR = 'horus_user';
    const SESSION_UID = 'horus_user_id';
    const SESSION_ROLES = 'horus_roles';
    const SESSION_IS_ADMIN = 'horus_is_admin';
    const SESSION_TOKEN = 'horus_token';

    const authOverlay = document.getElementById('authOverlay');
    const appContainer = document.getElementById('appContainer');
    const loginBox = document.getElementById('loginBox');
    const registerBox = document.getElementById('registerBox');

    const loginForm = document.getElementById('loginForm');
    const registerForm = document.getElementById('registerForm');

    const loginError = document.getElementById('loginError');
    const registerError = document.getElementById('registerError');
    const registerOk = document.getElementById('registerSuccess');

    const goRegister = document.getElementById('goRegister');
    const goLogin = document.getElementById('goLogin');

    const sessionUser = document.getElementById('sessionUser');
    const logoutBtn = document.getElementById('logoutBtn');

    const adminUsersBtn = document.getElementById('adminUsersBtn');
    const adminUsersCard = document.getElementById('adminUsersCard');
    const adminUsersRefreshBtn = document.getElementById('adminUsersRefreshBtn');
    const adminUsersCloseBtn = document.getElementById('adminUsersCloseBtn');

    const adminCreateUserForm = document.getElementById('adminCreateUserForm');
    const adminNewFullName = document.getElementById('adminNewFullName');
    const adminNewUsername = document.getElementById('adminNewUsername');
    const adminNewEmail = document.getElementById('adminNewEmail');
    const adminNewPassword = document.getElementById('adminNewPassword');
    const adminNewIsAdmin = document.getElementById('adminNewIsAdmin');
    const adminNewIsActive = document.getElementById('adminNewIsActive');
    const adminCreateMsg = document.getElementById('adminCreateMsg');

    const adminEditUserForm = document.getElementById('adminEditUserForm');
    const adminEditUserId = document.getElementById('adminEditUserId');
    const adminEditFullName = document.getElementById('adminEditFullName');
    const adminEditUsername = document.getElementById('adminEditUsername');
    const adminEditEmail = document.getElementById('adminEditEmail');
    const adminEditPassword = document.getElementById('adminEditPassword');
    const adminEditIsAdmin = document.getElementById('adminEditIsAdmin');
    const adminEditIsActive = document.getElementById('adminEditIsActive');
    const adminEditCancelBtn = document.getElementById('adminEditCancelBtn');
    const adminEditMsg = document.getElementById('adminEditMsg');

    const adminUsersBody = document.getElementById('adminUsersBody');
    const adminUsersTable = document.getElementById('adminUsersTable');
    const adminUsersEmpty = document.getElementById('adminUsersEmpty');

    let currentUser = null;
    let cachedUsers = [];

    function getToken() {
        return sessionStorage.getItem(SESSION_TOKEN) || '';
    }

    function clearSession() {
        sessionStorage.removeItem(SESSION_KEY);
        sessionStorage.removeItem(SESSION_USR);
        sessionStorage.removeItem(SESSION_UID);
        sessionStorage.removeItem(SESSION_ROLES);
        sessionStorage.removeItem(SESSION_IS_ADMIN);
        sessionStorage.removeItem(SESSION_TOKEN);
        currentUser = null;
    }

    function saveSession(token, user) {
        const roles = Array.isArray(user?.roles) ? user.roles : [];

        sessionStorage.setItem(SESSION_KEY, '1');
        sessionStorage.setItem(SESSION_USR, String(user?.username || ''));
        sessionStorage.setItem(SESSION_UID, String(user?.id || ''));
        sessionStorage.setItem(SESSION_ROLES, JSON.stringify(roles));
        sessionStorage.setItem(SESSION_IS_ADMIN, user?.is_admin ? '1' : '0');
        sessionStorage.setItem(SESSION_TOKEN, token);

        currentUser = {
            id: Number.parseInt(String(user?.id || ''), 10) || null,
            username: String(user?.username || ''),
            is_admin: Boolean(user?.is_admin),
            roles
        };
    }

    function escapeHtml(value) {
        return String(value ?? '')
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    function formatDate(value) {
        if (!value) {
            return '--';
        }

        const date = new Date(value);
        if (Number.isNaN(date.getTime())) {
            return String(value);
        }

        return date.toLocaleString();
    }

    function isValidEmail(value) {
        return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/i.test(String(value || '').trim());
    }

    function isValidUsername(value) {
        return /^[a-zA-Z0-9_.-]{3,40}$/.test(String(value || '').trim());
    }

    async function apiRequest(path, options = {}) {
        const token = getToken();
        const headers = {
            ...(options.headers || {})
        };

        if (token) {
            headers.Authorization = `Bearer ${token}`;
        }

        const response = await fetch(path, {
            ...options,
            headers
        });

        const payload = await response.json().catch(() => ({}));
        if (!response.ok) {
            const err = new Error(payload.error || `Error del servidor (${response.status})`);
            err.status = response.status;
            err.payload = payload;
            throw err;
        }

        return payload;
    }

    function showApp(user) {
        authOverlay.style.display = 'none';
        appContainer.style.display = 'block';

        if (sessionUser) {
            const adminTag = user?.is_admin ? ' | ADMIN' : '';
            sessionUser.textContent = `[ ${user?.username || ''}${adminTag} ]`;
        }

        if (adminUsersBtn) {
            adminUsersBtn.style.display = user?.is_admin ? 'inline-flex' : 'none';
        }

        if (!user?.is_admin) {
            hideAdminPanel();
        }

        document.dispatchEvent(new CustomEvent('horus:session-ready'));
    }

    function showLogin() {
        appContainer.style.display = 'none';
        authOverlay.style.display = 'flex';
        loginBox.style.display = 'flex';
        registerBox.style.display = 'none';
        clearErrors();
    }

    function showRegister() {
        loginBox.style.display = 'none';
        registerBox.style.display = 'flex';
        clearErrors();
    }

    function clearErrors() {
        loginError.style.display = 'none';
        registerError.style.display = 'none';
        registerOk.style.display = 'none';
        loginError.textContent = 'Credenciales incorrectas';
        registerError.textContent = '';

        if (adminCreateMsg) {
            adminCreateMsg.textContent = '';
            adminCreateMsg.className = 'admin-users-form__msg';
        }

        if (adminEditMsg) {
            adminEditMsg.textContent = '';
            adminEditMsg.className = 'admin-users-form__msg';
        }
    }

    function hideAdminPanel() {
        if (adminUsersCard) {
            adminUsersCard.style.display = 'none';
        }

        if (adminEditUserForm) {
            adminEditUserForm.style.display = 'none';
        }
    }

    function toggleAdminPanel() {
        if (!currentUser?.is_admin || !adminUsersCard) {
            return;
        }

        const shouldShow = adminUsersCard.style.display === 'none' || !adminUsersCard.style.display;
        adminUsersCard.style.display = shouldShow ? '' : 'none';

        if (shouldShow) {
            loadUsers();
        }
    }

    function setCreateMessage(message, ok = false) {
        if (!adminCreateMsg) {
            return;
        }

        adminCreateMsg.textContent = message || '';
        adminCreateMsg.className = `admin-users-form__msg ${ok ? 'admin-users-form__msg--ok' : 'admin-users-form__msg--error'}`;
    }

    function setEditMessage(message, ok = false) {
        if (!adminEditMsg) {
            return;
        }

        adminEditMsg.textContent = message || '';
        adminEditMsg.className = `admin-users-form__msg ${ok ? 'admin-users-form__msg--ok' : 'admin-users-form__msg--error'}`;
    }

    function renderUsersTable(users) {
        cachedUsers = Array.isArray(users) ? users : [];
        adminUsersBody.innerHTML = '';

        if (!cachedUsers.length) {
            adminUsersTable.querySelector('thead').style.display = 'none';
            adminUsersEmpty.style.display = 'block';
            return;
        }

        adminUsersTable.querySelector('thead').style.display = '';
        adminUsersEmpty.style.display = 'none';

        cachedUsers.forEach((user, index) => {
            const tr = document.createElement('tr');
            tr.style.animation = `fadeSlideUp 0.35s ease ${index * 0.03}s both`;

            const role = user.is_admin ? 'ADMIN' : 'USER';
            const active = user.is_active ? 'Sí' : 'No';
            const email = user.email || '--';
            const username = user.username || '--';
            const fullName = user.full_name || '--';

            tr.innerHTML = `
                <td>${user.id}</td>
                <td>${escapeHtml(username)}</td>
                <td>${escapeHtml(fullName)}</td>
                <td>${escapeHtml(email)}</td>
                <td>${role}</td>
                <td>${active}</td>
                <td>${escapeHtml(formatDate(user.last_login))}</td>
                <td>
                    <button class="btn-scan-device admin-action" data-action="edit" data-user-id="${user.id}">EDITAR</button>
                    <button class="btn-scan-device admin-action admin-action--danger" data-action="delete" data-user-id="${user.id}">ELIMINAR</button>
                </td>
            `;

            adminUsersBody.appendChild(tr);
        });
    }

    function openEditForm(userId) {
        const user = cachedUsers.find((item) => item.id === userId);
        if (!user) {
            return;
        }

        adminEditUserId.value = String(user.id);
        adminEditFullName.value = user.full_name || '';
        adminEditUsername.value = user.username || '';
        adminEditEmail.value = user.email || '';
        adminEditPassword.value = '';
        adminEditIsAdmin.checked = Boolean(user.is_admin);
        adminEditIsActive.checked = Boolean(user.is_active);

        setEditMessage('');
        adminEditUserForm.style.display = '';
        adminEditUserForm.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }

    async function loadUsers() {
        if (!currentUser?.is_admin) {
            return;
        }

        try {
            const payload = await apiRequest(API_ADMIN_USERS, { method: 'GET' });
            renderUsersTable(payload.items || []);
        } catch (error) {
            setCreateMessage(`No se pudieron cargar usuarios: ${error.message}`);
        }
    }

    async function handleCreateUser(event) {
        event.preventDefault();

        const fullName = adminNewFullName.value.trim();
        const username = adminNewUsername.value.trim().toLowerCase();
        const email = adminNewEmail.value.trim().toLowerCase();
        const password = adminNewPassword.value;

        if (!fullName || !username || !email || !password) {
            setCreateMessage('Nombre completo, usuario, correo y contraseña son obligatorios');
            return;
        }

        if (fullName.length < 3) {
            setCreateMessage('El nombre completo debe tener al menos 3 caracteres');
            return;
        }

        if (!isValidUsername(username)) {
            setCreateMessage('Usuario inválido (3-40, letras, números, ., _, -)');
            return;
        }

        if (!isValidEmail(email)) {
            setCreateMessage('Formato de correo inválido');
            return;
        }

        try {
            await apiRequest(API_ADMIN_USERS, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    full_name: fullName,
                    username,
                    email,
                    password,
                    is_admin: adminNewIsAdmin.checked,
                    is_active: adminNewIsActive.checked
                })
            });

            adminCreateUserForm.reset();
            adminNewIsActive.checked = true;
            setCreateMessage('Usuario creado correctamente', true);
            await loadUsers();
        } catch (error) {
            setCreateMessage(error.message || 'No se pudo crear el usuario');
        }
    }

    async function handleEditUser(event) {
        event.preventDefault();

        const userId = Number.parseInt(adminEditUserId.value, 10);
        if (!Number.isFinite(userId) || userId <= 0) {
            setEditMessage('ID de usuario inválido');
            return;
        }

        const fullName = adminEditFullName.value.trim();
        const username = adminEditUsername.value.trim().toLowerCase();
        const email = adminEditEmail.value.trim().toLowerCase();

        if (!fullName || fullName.length < 3) {
            setEditMessage('Debes ingresar un nombre completo válido (mínimo 3 caracteres)');
            return;
        }

        if (!username || !isValidUsername(username)) {
            setEditMessage('Debes ingresar un usuario válido (3-40, letras, números, ., _, -)');
            return;
        }

        if (!email || !isValidEmail(email)) {
            setEditMessage('Debes ingresar un correo válido');
            return;
        }

        const payload = {
            full_name: fullName,
            username,
            email,
            is_admin: adminEditIsAdmin.checked,
            is_active: adminEditIsActive.checked
        };

        if (adminEditPassword.value.trim()) {
            payload.password = adminEditPassword.value;
        }

        try {
            await apiRequest(API_ADMIN_USERS + '/' + userId, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });

            setEditMessage('Usuario actualizado', true);
            await loadUsers();
        } catch (error) {
            setEditMessage(error.message || 'No se pudo actualizar el usuario');
        }
    }

    async function handleDeleteUser(userId) {
        if (!Number.isFinite(userId) || userId <= 0) {
            return;
        }

        const confirmed = window.confirm(`¿Eliminar usuario #${userId}?`);
        if (!confirmed) {
            return;
        }

        try {
            await apiRequest(`${API_ADMIN_USERS}/${userId}`, {
                method: 'DELETE'
            });

            setCreateMessage(`Usuario #${userId} eliminado`, true);
            if (Number.parseInt(adminEditUserId.value, 10) === userId) {
                adminEditUserForm.style.display = 'none';
            }
            await loadUsers();
        } catch (error) {
            setCreateMessage(error.message || 'No se pudo eliminar el usuario');
        }
    }

    async function bootstrapSession() {
        const token = getToken();
        if (!token) {
            clearSession();
            showLogin();
            return;
        }

        try {
            const payload = await apiRequest(`${API_AUTH}/me`, { method: 'GET' });
            const user = payload.user;

            saveSession(token, user);
            showApp(user);
        } catch {
            clearSession();
            showLogin();
        }
    }

    goRegister.addEventListener('click', showRegister);
    goLogin.addEventListener('click', function () {
        registerBox.style.display = 'none';
        loginBox.style.display = 'flex';
        clearErrors();
    });

    loginForm.addEventListener('submit', async function (e) {
        e.preventDefault();

        const username = document.getElementById('loginUser').value.trim();
        const password = document.getElementById('loginPass').value;

        try {
            const payload = await apiRequest(`${API_AUTH}/login`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
            });

            saveSession(payload.token, payload.user);
            document.getElementById('loginPass').value = '';
            showApp(payload.user);
        } catch (error) {
            loginError.textContent = error.message || 'Credenciales incorrectas';
            loginError.style.display = 'block';
            document.getElementById('loginPass').value = '';
            loginBox.classList.remove('shake');
            void loginBox.offsetWidth;
            loginBox.classList.add('shake');
        }
    });

    registerForm.addEventListener('submit', async function (e) {
        e.preventDefault();

        const fullName = document.getElementById('regFullName').value.trim();
        const username = document.getElementById('regUsername').value.trim().toLowerCase();
        const email = document.getElementById('regEmail').value.trim().toLowerCase();
        const password = document.getElementById('regPass').value;
        const password2 = document.getElementById('regPass2').value;

        registerError.style.display = 'none';
        registerOk.style.display = 'none';

        if (!fullName) {
            registerError.textContent = 'El nombre completo es obligatorio';
            registerError.style.display = 'block';
            return;
        }

        if (fullName.length < 3) {
            registerError.textContent = 'El nombre completo debe tener al menos 3 caracteres';
            registerError.style.display = 'block';
            return;
        }

        if (!username) {
            registerError.textContent = 'El nombre de usuario es obligatorio';
            registerError.style.display = 'block';
            return;
        }

        if (!isValidUsername(username)) {
            registerError.textContent = 'Usuario inválido (3-40, letras, números, ., _, -)';
            registerError.style.display = 'block';
            return;
        }

        if (!email) {
            registerError.textContent = 'El correo es obligatorio';
            registerError.style.display = 'block';
            return;
        }

        if (!isValidEmail(email)) {
            registerError.textContent = 'Formato de correo inválido';
            registerError.style.display = 'block';
            return;
        }

        if (password.length < 6) {
            registerError.textContent = 'La contraseña debe tener al menos 6 caracteres';
            registerError.style.display = 'block';
            return;
        }

        if (password !== password2) {
            registerError.textContent = 'Las contraseñas no coinciden';
            registerError.style.display = 'block';
            return;
        }

        try {
            const payload = await apiRequest(API_AUTH + '/register', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    full_name: fullName,
                    username,
                    email,
                    password
                })
            });

            registerForm.reset();
            registerOk.style.display = 'block';
            saveSession(payload.token, payload.user);

            setTimeout(function () {
                showApp(payload.user);
            }, 800);
        } catch (error) {
            registerError.textContent = error.message || 'No se pudo crear la cuenta';
            registerError.style.display = 'block';
            registerBox.classList.remove('shake');
            void registerBox.offsetWidth;
            registerBox.classList.add('shake');
        }
    });

    if (logoutBtn) {
        logoutBtn.addEventListener('click', async function () {
            try {
                await apiRequest(`${API_AUTH}/logout`, { method: 'POST' });
            } catch {
                // no-op
            }

            clearSession();
            hideAdminPanel();
            showLogin();
        });
    }

    if (adminUsersBtn) {
        adminUsersBtn.addEventListener('click', toggleAdminPanel);
    }

    if (adminUsersRefreshBtn) {
        adminUsersRefreshBtn.addEventListener('click', loadUsers);
    }

    if (adminUsersCloseBtn) {
        adminUsersCloseBtn.addEventListener('click', hideAdminPanel);
    }

    if (adminCreateUserForm) {
        adminCreateUserForm.addEventListener('submit', handleCreateUser);
    }

    if (adminEditUserForm) {
        adminEditUserForm.addEventListener('submit', handleEditUser);
    }

    if (adminEditCancelBtn) {
        adminEditCancelBtn.addEventListener('click', function () {
            adminEditUserForm.style.display = 'none';
            setEditMessage('');
        });
    }

    if (adminUsersBody) {
        adminUsersBody.addEventListener('click', function (event) {
            const actionBtn = event.target.closest('.admin-action');
            if (!actionBtn) {
                return;
            }

            const userId = Number.parseInt(actionBtn.dataset.userId || '', 10);
            if (!Number.isFinite(userId) || userId <= 0) {
                return;
            }

            const action = actionBtn.dataset.action;
            if (action === 'edit') {
                openEditForm(userId);
            } else if (action === 'delete') {
                handleDeleteUser(userId);
            }
        });
    }

    bootstrapSession();
})();
