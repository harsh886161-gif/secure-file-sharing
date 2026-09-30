const fileInput = document.getElementById("fileInput");
const fileName = document.getElementById("fileName");
const uploadForm = document.getElementById("uploadForm");
const uploadButton = document.getElementById("uploadButton");
const loading = document.getElementById("loading");


if (fileInput) {

    fileInput.addEventListener("change", function () {

        if (fileInput.files.length > 0) {

            fileName.textContent =
                fileInput.files[0].name;

        } else {

            fileName.textContent =
                "No file selected";
        }

    });

}


if (uploadForm) {

    uploadForm.addEventListener("submit", function () {

        if (!fileInput.files.length) {
            return;
        }

        uploadButton.disabled = true;

        uploadButton.textContent =
            "Uploading...";

        loading.classList.remove("hidden");

    });

}