$(document).ready(() => {
    if ($('.toc').length === 0) {
        return
    }

    $('.toc').prepend('<i class="fa float-right fa-caret-down collapse-all-toggle"></i>')
    $('article').append($('.toc').clone().addClass('side-toc'))
    $('.side-toc').prepend('<i class="fa fa-arrow-up scrolltop"></i>')
    $('.side-toc').prepend('<i class="fa fa-list-ul handle"></i>')


    let toc_list = $('.toc ul li:has(ul)')
    toc_list.addClass('collapsible')
    toc_list.prepend('<i class="fa fa-caret-down collapse-toggle"></i>')

    $('.collapse-all-toggle').click((event) => {
        let self = $(event.target)


        if (self.hasClass('collapsed')) {
            self.removeClass('collapsed')
            self.removeClass('fa-caret-up')
            self.addClass('fa-caret-down')
            $(self).parent().find('.collapse-toggle.collapsed').click()
        } else {
            self.removeClass('fa-caret-down')
            self.addClass('fa-caret-up')
            self.addClass('collapsed')
            $(self).parent().find('.collapse-toggle:not(.collapsed)').click()
        }
    });

    $('.collapse-toggle').click((event) => {
        let self = $(event.target)

        if (self.hasClass('collapsed')) {
            self.removeClass('collapsed')
            self.removeClass('fa-caret-right')
            self.addClass('fa-caret-down')
            self.parent().find('ul').first().removeClass('collapsed-item')
        } else {
            self.removeClass('fa-caret-down')
            self.addClass('fa-caret-right')
            self.addClass('collapsed')
            self.parent().find('ul').first().addClass('collapsed-item')
        }

    });


    $('.side-toc .scrolltop').click((event) => {
        window.scrollTo({ top: 0, behavior: 'smooth' });
        $(event.target).parents('.side-toc').find('.handle').click()
    });

    $('.side-toc .handle').click((event) => {
        let parent = $(event.target).parent()

        if (parent.hasClass('active')) {
            parent.removeClass('active')
        }
        else {
            parent.addClass('active')
        }
    });

    $('.side-toc a').click((event) => {
        $(event.target).parents('.side-toc').find('.handle').click()
    });

    const tocOffset = $('.toc').offset().top;
    $(window).scroll(function () {
        let sideToc = $('.side-toc');
        let scroll = $(window).scrollTop();

        if (scroll >= tocOffset + $('.toc').height()) {
            sideToc.addClass('fixed');
        }
        else {
            sideToc.removeClass('fixed');
        }

    });

    $('.collapse-all-toggle').click()

    $(document).on('keydown', function (e) {
        if($('.stork-input:focus').length > 0) return;
        const isSideToc = $('.side-toc.fixed').length > 0;
        const toc = isSideToc ? $('.side-toc.fixed') : $('.toc');
        if (toc.length > 0) {
            let currentHighlightedElement = toc.find('li.highlighted');
            switch (e.which) {
                case 37: // Arrow left
                    if (toc.hasClass('focused')) {
                        const toggle = currentHighlightedElement.find('.collapse-toggle:not(.collapsed)');
                        if (currentHighlightedElement.hasClass('collapsible') && toggle.length > 0) {
                            if (toggle.length > 0) {
                                toggle.click();
                            }
                        }
                    }
                    break;
                case 38: // Arrow up
                    if (toc.hasClass('focused')) {
                        const prev = currentHighlightedElement.prev('li');
                        const element = prev.length > 0 ? prev : currentHighlightedElement.parent('ul').parent('li');
                        if (element.length > 0) {
                            currentHighlightedElement.removeClass('highlighted');
                            element.addClass('highlighted')
                        }
                        e.preventDefault();
                    }
                    break;
                case 39: // Arrow right
                    if (toc.hasClass('focused')) {
                        if (currentHighlightedElement.hasClass('collapsible')) {
                            const toggle = currentHighlightedElement.find('.collapse-toggle.collapsed');
                            const isCollapsed = toggle.length > 0;

                            if(!isCollapsed){
                                currentHighlightedElement.removeClass('highlighted');
                                currentHighlightedElement.find('li').first().addClass('highlighted')
                            }else{
                                const toggle = currentHighlightedElement.find('.collapse-toggle.collapsed');
                                if (toggle.length > 0) {
                                    toggle.click();
                                }
                            }
                        }
                    }
                    break;
                case 40: // Arrow down
                    if (toc.hasClass('focused')) {
                        const next = currentHighlightedElement.next('li');
                        const element = next.length > 0 ? next : currentHighlightedElement.parent('ul').parent('li').next('li');
                        if (element.length > 0) {
                            currentHighlightedElement.removeClass('highlighted');
                            element.addClass('highlighted')
                        }
                        e.preventDefault();
                    }
                    break;
                case 13: // Enter
                    if (toc.hasClass('focused')) {
                        currentHighlightedElement.find('a')[0].click();
                        toc.removeClass('focused');
                        toc.find('.highlighted').removeClass('highlighted');
                    }
                    break;
            }
            currentHighlightedElement = toc.find('li.highlighted');

            if (toc.hasClass('focused')) {
                let highlightedOffset = currentHighlightedElement.offset().top;
                if (isSideToc) {
                    highlightedOffset -= toc.offset().top;
                    toc[0].scrollTo({ top: toc.scrollTop() + highlightedOffset, behavior: 'smooth' });

                } else {
                    topBoundary = $(window).scrollTop() + $(window).height();
                    bottomBoundary = $(window).scrollTop();
                    if (bottomBoundary > highlightedOffset || highlightedOffset > topBoundary) {
                        window.scrollTo({ top: highlightedOffset, behavior: 'smooth' });
                    }
                }
            }


        }
    });

    $(document).on('keypress', function (e) {
        if($('.stork-input:focus').length > 0) return;
        const isSideToc = $('.side-toc.fixed').length > 0;
        const toc = isSideToc > 0 ? $('.side-toc.fixed') : $('.toc');
        if (toc.length > 0) {
            switch (e.which) {
                case 76:
                    toc.find('.collapse-all-toggle').click();
                    break;
                case 108:
                    if (isSideToc) toc.find('.handle').click();

                    if (toc.hasClass('focused')) {
                        if (!isSideToc || !toc.hasClass('active')) {
                            toc.removeClass('focused');
                            toc.find('.highlighted').removeClass('highlighted');
                        }
                    } else {
                        toc.addClass('focused');
                        toc.find('li').first().addClass('highlighted');
                    }
            }
        }
    });
});
