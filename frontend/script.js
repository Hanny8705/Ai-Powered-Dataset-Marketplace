document.addEventListener("DOMContentLoaded", function () {

    const loginForm =
        document.getElementById("loginForm");

    if (!loginForm) {
        return;
    }


    loginForm.addEventListener(
        "submit",
        function (event) {

            event.preventDefault();


            const email =
                document.getElementById("email").value.trim();

            const password =
                document.getElementById("password").value.trim();

            const role =
                document.getElementById("role").value;


            /*
             * Basic validation
             */

            if (!email || !password || !role) {
                return;
            }


            /*
             * SELLER LOGIN
             */

            if (role === "seller") {

                window.location.href =
                    "seller.html";

                return;
            }


            /*
             * BUYER LOGIN
             *
             * No popup.
             * Directly opens buyer.html.
             */

            if (role === "buyer") {

                window.location.href =
                    "buyer.html";

                return;
            }

        }
    );

});