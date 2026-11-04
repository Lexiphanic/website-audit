// Runs before the page body renders: drop the no-JS fallback class as early as
// possible so reveal animations start from their hidden state without a flash.
document.documentElement.classList.remove("no-js");
