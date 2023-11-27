document.addEventListener('DOMContentLoaded', function () {
    // Selector de formulario
    const form = document.getElementById('registerForm');

    // Selector de campos
    const username = document.getElementById('username');
    const email = document.getElementById('email');
    const password = document.getElementById('password');
    const confirmPassword = document.getElementById('confirm_password');

    // Eventos de entrada para la validación en tiempo real
    username.addEventListener('input', function () {
        validateUsername(username.value);
    });

    email.addEventListener('input', function () {
        validateEmail(email.value);
    });

    password.addEventListener('input', function () {
        validatePassword(password.value);
        // Validar la coincidencia de contraseñas al escribir la contraseña
        validateConfirmPassword(password.value, confirmPassword.value);
    });

    confirmPassword.addEventListener('input', function () {
        validateConfirmPassword(password.value, confirmPassword.value);
    });

    // Evento de envío del formulario
    form.addEventListener('submit', function (event) {
        // Verificar cada campo al enviar el formulario
        if (!validateUsername(username.value)) {
            event.preventDefault();
        }

        if (!validateEmail(email.value)) {
            event.preventDefault();
        }

        if (!validatePassword(password.value)) {
            event.preventDefault();
        }

        if (!validateConfirmPassword(password.value, confirmPassword.value)) {
            event.preventDefault();
        }
    });

     // Función para validar el nombre de usuario
     function validateUsername(username) {
        // Implementa tu lógica de validación para el nombre de usuario
        const isValidLength = username.length > 0 && username.length <= 10;
        const isValidFormat = /^[a-zA-Z0-9_-]+$/.test(username);

        if (isValidLength && isValidFormat) {
            showSuccessMessage('username-success', 'Ok!', 'username');
        } else {
            showErrorMessage('username-error', 'Virheellinen käyttäjätunnus. Enintään 10 merkkiä,vain numeroja,kirjaimia sekä "_" tai "-" ', 'username');
        }
        
        return isValidLength && isValidFormat;
    }

    // Función para validar la dirección de correo electrónico
    function validateEmail(email) {
        // Implementa tu lógica de validación para la dirección de correo electrónico
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        const isValid = emailRegex.test(email);
        if (isValid) {
            showSuccessMessage('email-success', 'Valid!', 'email');
        } else {
            showErrorMessage('email-error', 'Kirjoita oikein sähköpostisi, esim email@email.org', 'email');
        }
        return isValid;
    }

    // Función para validar la contraseña
    function validatePassword(password) {
        // Implementa tu lógica de validación para la contraseña
        const isValid = password.length >= 8;
        if (isValid) {
            showSuccessMessage('password-success', 'Ok!', 'password');
        } else {
            showErrorMessage('password-error', 'Väärä salasana. On oltava vähintään 8 merkkiä pitkä', 'password');
        }
        return isValid;
    }

    // Función para validar la coincidencia de contraseñas
    function validateConfirmPassword(password, confirmPassword) {
        // Implementa tu lógica de validación para la coincidencia de contraseñas
        const isValid = password === confirmPassword;
        if (isValid) {
            showSuccessMessage('confirm_password-success', 'Ok! salasanat täsmäävät', 'confirm_password');
        } else {
            showErrorMessage('confirm_password-error', 'Salasanat eivät täsmää', 'confirm_password');
        }
        return isValid;
    }

    function showSuccessMessage(elementId, message, field) {
        const successDiv = document.getElementById(`${field}-success`);
        const errorDiv = document.getElementById(`${field}-error`);
        const inputField = document.getElementById(field);
    
        successDiv.textContent = message;
        successDiv.style.display = 'block';
        successDiv.classList.remove('alert-danger');
        successDiv.classList.add('alert-success');
        errorDiv.style.display = 'none';
    
        // Agregar la clase Bootstrap is-valid y quitar is-invalid
        inputField.classList.remove('is-invalid');
        inputField.classList.add('is-valid');
    }
    
    // Función para mostrar un mensaje de error
    function showErrorMessage(elementId, message, field) {
        const errorDiv = document.getElementById(`${field}-error`);
        const successDiv = document.getElementById(`${field}-success`);
        const inputField = document.getElementById(field);
    
        errorDiv.textContent = message;
        errorDiv.style.display = 'block';
        errorDiv.classList.remove('alert-success');
        errorDiv.classList.add('alert-danger');
        successDiv.style.display = 'none';
    
        // Agregar la clase Bootstrap is-invalid y quitar is-valid
        inputField.classList.remove('is-valid');
        inputField.classList.add('is-invalid');
    }
});
