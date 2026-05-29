document.addEventListener('DOMContentLoaded', () => {
    const burger = document.getElementById('burgerBtn');
    const navMenu = document.getElementById('navMenu');
    if (burger && navMenu) {
        burger.addEventListener('click', (e) => {
            e.preventDefault();
            navMenu.classList.toggle('active');
            document.body.style.overflow = navMenu.classList.contains('active') ? 'hidden' : '';
        });
        const links = navMenu.querySelectorAll('a');
        links.forEach(link => {
            link.addEventListener('click', () => {
                navMenu.classList.remove('active');
                document.body.style.overflow = '';
            });
        });
        document.addEventListener('click', (e) => {
            if (navMenu.classList.contains('active') && !burger.contains(e.target) && !navMenu.contains(e.target)) {
                navMenu.classList.remove('active');
                document.body.style.overflow = '';
            }
        });
    }
    // Закрытие алертов
    document.querySelectorAll('.close-alert').forEach(btn => {
        btn.addEventListener('click', () => btn.parentElement.remove());
    });
    setTimeout(() => {
        document.querySelectorAll('.alert').forEach(alert => {
            alert.style.transition = 'opacity 0.5s';
            alert.style.opacity = '0';
            setTimeout(() => alert.remove(), 500);
        });
    }, 5000);
});