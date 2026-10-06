document.addEventListener("DOMContentLoaded", function () {

    /* =========================================================
       CONFIGURATION
    ========================================================= */

    const API_BASE_URL = "http://127.0.0.1:8000";

    const TOKEN_KEY = "authToken";
    const ROLE_KEY = "userRole";
    const USER_KEY = "currentUser";


    /* =========================================================
       COMMON HELPERS
    ========================================================= */

    function saveAuth(token, role, user = null) {

        if (!token) {
            console.error("No authentication token received.");
            return false;
        }

        localStorage.setItem(TOKEN_KEY, token);

        if (role) {
            localStorage.setItem(ROLE_KEY, role);
        }

        if (user) {
            localStorage.setItem(
                USER_KEY,
                JSON.stringify(user)
            );
        }

        return true;
    }


    function getToken() {
        return localStorage.getItem(TOKEN_KEY);
    }


    function getRole() {
        return localStorage.getItem(ROLE_KEY);
    }


    function getCurrentUser() {

        const user = localStorage.getItem(USER_KEY);

        if (!user) {
            return null;
        }

        try {
            return JSON.parse(user);
        } catch (error) {
            return null;
        }
    }


    function logout() {

        localStorage.removeItem(TOKEN_KEY);
        localStorage.removeItem(ROLE_KEY);
        localStorage.removeItem(USER_KEY);

        window.location.href = "index.html";
    }


    /*
     * This helper can be used by upload.html,
     * analysis.html, seller.html, buyer.html, etc.
     */
    async function authenticatedFetch(url, options = {}) {

        const token = getToken();

        if (!token) {

            alert("Your login session has expired. Please login again.");

            window.location.href = "index.html";

            throw new Error("Authorization token required.");
        }


        const headers = {
            ...(options.headers || {}),
            "Authorization": `Bearer ${token}`
        };


        return fetch(url, {
            ...options,
            headers: headers
        });
    }


    /*
     * Make helpers available globally.
     */
    window.getAuthToken = getToken;
    window.getUserRole = getRole;
    window.getCurrentUser = getCurrentUser;
    window.logoutUser = logout;
    window.authenticatedFetch = authenticatedFetch;


    /* =========================================================
       LOGIN FORM
    ========================================================= */

    const loginForm =
        document.getElementById("loginForm");


    if (loginForm) {

        loginForm.addEventListener(
            "submit",
            async function (event) {

                event.preventDefault();


                const emailElement =
                    document.getElementById("email");

                const passwordElement =
                    document.getElementById("password");

                const roleElement =
                    document.getElementById("role");


                if (
                    !emailElement ||
                    !passwordElement ||
                    !roleElement
                ) {
                    console.error(
                        "Login form fields are missing."
                    );

                    return;
                }


                const email =
                    emailElement.value.trim();

                const password =
                    passwordElement.value.trim();

                const role =
                    roleElement.value;


                /* -----------------------------------------
                   VALIDATION
                ----------------------------------------- */

                if (!email) {

                    showMessage(
                        "Please enter your email.",
                        "error"
                    );

                    emailElement.focus();

                    return;
                }


                if (!password) {

                    showMessage(
                        "Please enter your password.",
                        "error"
                    );

                    passwordElement.focus();

                    return;
                }


                if (!role) {

                    showMessage(
                        "Please select your role.",
                        "error"
                    );

                    roleElement.focus();

                    return;
                }


                /* -----------------------------------------
                   BUTTON LOADING
                ----------------------------------------- */

                const submitButton =
                    loginForm.querySelector(
                        'button[type="submit"]'
                    );


                const originalButtonText =
                    submitButton
                        ? submitButton.textContent
                        : "";


                if (submitButton) {

                    submitButton.disabled = true;

                    submitButton.textContent =
                        "Logging in...";
                }


                clearMessage();


                try {

                    /* -----------------------------------------
                       LOGIN API
                    ----------------------------------------- */

                    const response = await fetch(
                        `${API_BASE_URL}/login`,
                        {
                            method: "POST",

                            headers: {
                                "Content-Type":
                                    "application/json"
                            },

                            body: JSON.stringify({
                                email: email,
                                password: password,
                                role: role
                            })
                        }
                    );


                    let result = {};

                    try {

                        result =
                            await response.json();

                    } catch (jsonError) {

                        result = {};
                    }


                    /* -----------------------------------------
                       LOGIN FAILED
                    ----------------------------------------- */

                    if (!response.ok) {

                        let errorMessage =
                            "Login failed. Please check your credentials.";

                        if (result.detail) {

                            if (
                                typeof result.detail ===
                                "string"
                            ) {
                                errorMessage =
                                    result.detail;
                            }

                            else if (
                                Array.isArray(
                                    result.detail
                                )
                            ) {

                                errorMessage =
                                    result.detail
                                        .map(
                                            item =>
                                                item.msg ||
                                                "Invalid input"
                                        )
                                        .join(", ");
                            }
                        }


                        showMessage(
                            errorMessage,
                            "error"
                        );

                        return;
                    }


                    /* -----------------------------------------
                       GET TOKEN
                    ----------------------------------------- */

                    const token =
                        result.access_token ||
                        result.token;


                    if (!token) {

                        console.error(
                            "Login response:",
                            result
                        );

                        showMessage(
                            "Login successful, but authentication token was not received.",
                            "error"
                        );

                        return;
                    }


                    /* -----------------------------------------
                       SAVE AUTHENTICATION
                    ----------------------------------------- */

                    const saved =
                        saveAuth(
                            token,
                            role,
                            result.user || {
                                email: email,
                                role: role
                            }
                        );


                    if (!saved) {

                        showMessage(
                            "Unable to save login session.",
                            "error"
                        );

                        return;
                    }


                    console.log(
                        "Authentication successful."
                    );

                    console.log(
                        "Role:",
                        role
                    );


                    /* -----------------------------------------
                       REDIRECT
                    ----------------------------------------- */

                    if (role === "seller") {

                        window.location.href =
                            "seller.html";

                        return;
                    }


                    if (role === "buyer") {

                        window.location.href =
                            "buyer.html";

                        return;
                    }


                    showMessage(
                        "Invalid account role.",
                        "error"
                    );

                }

                catch (error) {

                    console.error(
                        "Login error:",
                        error
                    );


                    showMessage(
                        "Cannot connect to the backend. Make sure FastAPI is running on http://127.0.0.1:8000",
                        "error"
                    );
                }

                finally {

                    if (submitButton) {

                        submitButton.disabled =
                            false;

                        submitButton.textContent =
                            originalButtonText;
                    }
                }

            }
        );
    }


    /* =========================================================
       REGISTER FORM
    ========================================================= */

    const registerForm =
        document.getElementById("registerForm");


    if (registerForm) {

        registerForm.addEventListener(
            "submit",
            async function (event) {

                event.preventDefault();


                const nameElement =
                    document.getElementById("registerName") ||
                    document.getElementById("name");

                const emailElement =
                    document.getElementById("registerEmail") ||
                    document.getElementById("email");

                const passwordElement =
                    document.getElementById("registerPassword") ||
                    document.getElementById("password");

                const roleElement =
                    document.getElementById("registerRole") ||
                    document.getElementById("role");


                if (
                    !nameElement ||
                    !emailElement ||
                    !passwordElement ||
                    !roleElement
                ) {

                    console.error(
                        "Registration form fields are missing."
                    );

                    return;
                }


                const name =
                    nameElement.value.trim();

                const email =
                    emailElement.value.trim();

                const password =
                    passwordElement.value.trim();

                const role =
                    roleElement.value;


                /* -----------------------------------------
                   VALIDATION
                ----------------------------------------- */

                if (!name) {

                    showMessage(
                        "Please enter your name.",
                        "error"
                    );

                    nameElement.focus();

                    return;
                }


                if (!email) {

                    showMessage(
                        "Please enter your email.",
                        "error"
                    );

                    emailElement.focus();

                    return;
                }


                /*
                 * Your backend accepts:
                 *
                 * hannykuhikar@40gmail
                 *
                 * because it only requires one @ and
                 * doesn't require .com/.in/etc.
                 */

                const emailPattern =
                    /^[^@\s]+@[^@\s]+$/;


                if (!emailPattern.test(email)) {

                    showMessage(
                        "Please enter a valid email format.",
                        "error"
                    );

                    emailElement.focus();

                    return;
                }


                if (!password) {

                    showMessage(
                        "Please enter a password.",
                        "error"
                    );

                    passwordElement.focus();

                    return;
                }


                if (password.length < 6) {

                    showMessage(
                        "Password must contain at least 6 characters.",
                        "error"
                    );

                    passwordElement.focus();

                    return;
                }


                if (!role) {

                    showMessage(
                        "Please select Buyer or Seller.",
                        "error"
                    );

                    roleElement.focus();

                    return;
                }


                clearMessage();


                const submitButton =
                    registerForm.querySelector(
                        'button[type="submit"]'
                    );


                const originalButtonText =
                    submitButton
                        ? submitButton.textContent
                        : "";


                if (submitButton) {

                    submitButton.disabled = true;

                    submitButton.textContent =
                        "Creating account...";
                }


                try {

                    /* -----------------------------------------
                       REGISTER API
                    ----------------------------------------- */

                    const response =
                        await fetch(
                            `${API_BASE_URL}/register`,
                            {
                                method: "POST",

                                headers: {
                                    "Content-Type":
                                        "application/json"
                                },

                                body: JSON.stringify({
                                    name: name,
                                    email: email,
                                    password: password,
                                    role: role
                                })
                            }
                        );


                    let result = {};

                    try {

                        result =
                            await response.json();

                    } catch (jsonError) {

                        result = {};
                    }


                    if (!response.ok) {

                        let errorMessage =
                            "Registration failed.";

                        if (result.detail) {

                            if (
                                typeof result.detail ===
                                "string"
                            ) {
                                errorMessage =
                                    result.detail;
                            }

                            else if (
                                Array.isArray(
                                    result.detail
                                )
                            ) {

                                errorMessage =
                                    result.detail
                                        .map(
                                            item =>
                                                item.msg ||
                                                "Invalid input"
                                        )
                                        .join(", ");
                            }
                        }


                        showMessage(
                            errorMessage,
                            "error"
                        );

                        return;
                    }


                    /* -----------------------------------------
                       REGISTRATION SUCCESS
                    ----------------------------------------- */

                    showMessage(
                        "Account created successfully. Please login.",
                        "success"
                    );


                    /*
                     * If registration API itself returns
                     * a token, save it.
                     *
                     * Otherwise user will login normally.
                     */

                    const token =
                        result.access_token ||
                        result.token;


                    if (token) {

                        saveAuth(
                            token,
                            role,
                            result.user || {
                                name: name,
                                email: email,
                                role: role
                            }
                        );


                        setTimeout(
                            function () {

                                if (
                                    role ===
                                    "seller"
                                ) {
                                    window.location.href =
                                        "seller.html";
                                }

                                else {

                                    window.location.href =
                                        "buyer.html";
                                }

                            },
                            500
                        );

                        return;
                    }


                    /*
                     * Registration does not return token.
                     * Go back to login form if available.
                     */

                    setTimeout(
                        function () {

                            const loginEmail =
                                document.getElementById(
                                    "email"
                                );

                            if (loginEmail) {
                                loginEmail.value =
                                    email;
                            }

                        },
                        500
                    );

                }

                catch (error) {

                    console.error(
                        "Registration error:",
                        error
                    );


                    showMessage(
                        "Cannot connect to the backend. Make sure FastAPI is running.",
                        "error"
                    );
                }

                finally {

                    if (submitButton) {

                        submitButton.disabled =
                            false;

                        submitButton.textContent =
                            originalButtonText;
                    }
                }

            }
        );
    }


    /* =========================================================
       LOGOUT BUTTON
    ========================================================= */

    const logoutButtons =
        document.querySelectorAll(
            "#logoutBtn, .logout-btn, [data-logout]"
        );


    logoutButtons.forEach(
        function (button) {

            button.addEventListener(
                "click",
                function (event) {

                    event.preventDefault();

                    logout();
                }
            );

        }
    );


    /* =========================================================
       MESSAGE FUNCTIONS
    ========================================================= */

    function showMessage(
        message,
        type = "error"
    ) {

        let messageBox =
            document.getElementById(
                "messageBox"
            );


        /*
         * If page doesn't already have a message box,
         * create one.
         */

        if (!messageBox) {

            messageBox =
                document.createElement("div");

            messageBox.id =
                "messageBox";


            messageBox.style.marginTop =
                "15px";

            messageBox.style.padding =
                "12px 16px";

            messageBox.style.borderRadius =
                "10px";

            messageBox.style.fontSize =
                "14px";


            const form =
                document.querySelector(
                    "form"
                );


            if (form) {
                form.appendChild(
                    messageBox
                );
            }

            else {
                document.body.appendChild(
                    messageBox
                );
            }
        }


        messageBox.textContent =
            message;


        if (type === "success") {

            messageBox.style.background =
                "#e8f7ee";

            messageBox.style.color =
                "#16743a";

            messageBox.style.border =
                "1px solid #b8e5c8";

        }

        else {

            messageBox.style.background =
                "#fff0f0";

            messageBox.style.color =
                "#c62828";

            messageBox.style.border =
                "1px solid #ffc7c7";
        }


        messageBox.style.display =
            "block";
    }


    function clearMessage() {

        const messageBox =
            document.getElementById(
                "messageBox"
            );


        if (messageBox) {

            messageBox.textContent =
                "";

            messageBox.style.display =
                "none";
        }
    }


    /* =========================================================
       DEBUG INFORMATION
    ========================================================= */

    console.log(
        "AI Dataset Marketplace script loaded."
    );


    console.log(
        "Logged in:",
        Boolean(getToken())
    );


    if (getToken()) {

        console.log(
            "Current role:",
            getRole()
        );
    }

});