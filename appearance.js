/* Aplica o tema escolhido em Ajustes antes do primeiro paint.
   Fica em arquivo próprio porque a CSP da página proíbe script inline. */
(function () {
  try {
    const value = localStorage.getItem('meucofre.appearance');
    if (value === 'light' || value === 'dark') {
      document.documentElement.setAttribute('data-appearance', value);
    }
  } catch (error) {
    /* Safari em navegação privada pode negar o localStorage. */
  }
})();
