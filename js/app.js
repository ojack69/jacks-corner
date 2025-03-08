// Check that service workers are supported
if ('serviceWorker' in navigator) {
    // Use the window load event to keep the page load performant
    window.addEventListener('load', () => {
        navigator.serviceWorker.register('/sw.js');
    });
};

// Sticky header
$(window).scroll(function () {
    let nav = $('nav');
    let scroll = $(window).scrollTop();

    if (scroll > nav.height()) {
        nav.addClass('fixed');
    }
    else {
        nav.removeClass('fixed');
    }
});

$(document).ready(function(){
    loadStorkIndex()
})
