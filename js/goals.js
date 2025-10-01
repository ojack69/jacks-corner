$(document).ready(()=>{
    
    $('[goal-group]').get().forEach((rawGroup)=>{
        let groupContent = ''
        let type = $(rawGroup).attr('goal-type')
        let timelineContent = ''

        // Creaate goals timeline
        $(rawGroup).parent().find('li:not([goal-group])').get().forEach((rawItem)=>{
            let type = ''
            let completion = ''
            let todo = ''
            let note = ''
            let icon = 'ellipsis'
            let completedOn = $(rawItem).attr('goal-completed')
            let goalNote = $(rawItem).attr('goal-note')
            
            if(completedOn != null){
                type = 'completed'
                icon = 'check'
                completion = timeInfoTemplate.replaceAll('{{content}}', 'Completed on: ' + completedOn) + '<br>'
            } else{
                type = 'todo'
            }

            let expiresOn = $(rawItem).attr('goal-expire')
            
            if(expiresOn != null){
                todo = '<br>' + timeInfoTemplate.replaceAll('{{content}}', 'To complete before: ' + expiresOn)
                
                if(type === 'todo'){
                    let parts = expiresOn.split("/") // Format is always dd/mm/yyyy
                    let parsedDate = new Date(parseInt(parts[2], 10), parseInt(parts[1], 10) - 1, parseInt(parts[0], 10))

                    if(parsedDate < new Date()){
                        type += ' past-due'
                        icon = 'times-circle'
                    }   
                } 

            }

            if(goalNote != null){
                note =  '<br>' + timeInfoTemplate.replaceAll('{{content}}', goalNote)
            }
            
            
            timelineContent += timelineItemTemplate.replaceAll('{{type}}', type).replaceAll('{{icon}}', icon)
            groupContent += itemTemplate.replaceAll('{{type}}', type).replaceAll('{{content}}', completion + $(rawItem).html() + todo + note)

        })

        // Insert newly created timeline
        $(rawGroup).parent().hide()
        $(rawGroup).parent().after(groupTemplate
            .replaceAll('{{term}}', $(rawGroup).attr('goal-type'))
            .replaceAll('{{title}}', $(rawGroup).html())
            .replaceAll('{{type}}', type)
            .replaceAll('{{content}}', groupContent)
            .replaceAll('{{timeline}}', timelineContent))
        
        // Set timeline line width
        let groupContainer = $(rawGroup).parent().next().next()
        let timelineWidth = 0;
        let minTimelineWidth = groupContainer.outerWidth()
        groupContainer.find('.goal-item').get().forEach((item)=>{
            timelineWidth += $(item).outerWidth() + 50
        })
        groupContainer.find('.goal-timeline-line').css('width', Math.max(timelineWidth, minTimelineWidth) + 'px')

        
        // Set next item active and scroll to it
        let nextItem = groupContainer.find('.goal-item.todo:not(.past-due)').first()
        if(nextItem != null){
            groupContainer.find('.goal-timeline-item.todo:not(.past-due)').first().addClass('active')
            let offset = nextItem.offset().left - groupContainer.offset().left
            groupContainer.scrollLeft(offset)
        }
    })

});


const groupTemplate =   '<h2 class="goal-title {{term}}">{{title}}</h2>'+
                        '<div class="goal-group-container">'+
                            '<div class="goal-group {{type}}">'+
                                '{{content}}'+
                            '</div>'+
                            '<div class="goal-timeline">'+
                                '{{timeline}}'+
                            '</div>'+
                            '<div class="goal-timeline-line"></div>'+
                       '</div>'

const itemTemplate = '<div class="goal-item {{type}}">{{content}}</div>'
const timeInfoTemplate = '<small>{{content}}</small>'

const timelineItemTemplate = '<div class="goal-timeline-item {{type}}">'+
                                '<i class="fa fa-{{icon}}"></i>'+
                                '<p class="goal-timeline-tick"></p>'+
                            '</div>'
