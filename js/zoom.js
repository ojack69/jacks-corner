//$(document).ready(() => {
//    $('article img').get().forEach((item) => {
//        let container = $(item).parent();    
//        container.append('<div class="zoom-overlay" style="margin-top: -' + item.height +'px; height: ' + item.height + 'px; background-image: url(\'' + item.attributes['src'].value + '\')"></div>');    
//    });
//
//    $('.zoom-overlay').click(function(e){
//        const _self = e.target;
//
//        $(_self).toggleClass('active');
//    })
//});


$(document).ready(() => {
    $('article img').click(function(e){
        const _self = e.target;
        console.log(_self)
        $(document.body).append('<div class="zoom-overlay"><img src="' + $(_self).attr('src') +'"></div>');    

        $('.zoom-overlay').click(function(e){
            $('.zoom-overlay').remove()
        })
    })
});

