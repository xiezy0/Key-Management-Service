/*
Author       : themes_mountain
Template Name: Cryptohub - Cryptocurrency HTML Template
Version      : 1.0
*/
(function($) {
	'use strict';
	
	jQuery(document).on('ready', function(){
	
		/*PRELOADER JS*/
		$(window).on('load', function() { 
			$('.status').fadeOut();
			$('.preloader').delay(350).fadeOut('slow'); 
		}); 
		/*END PRELOADER JS*/		
		
		/*START MENU JS*/		
		$('#main-menu').slicknav({
			label: '',
			duration: 1000,
			easingOpen: "easeOutBounce", //available with jQuery UI
			prependTo:'#mobile_menu',
			closeOnClick: true,
			easingClose:"swing", 
			easingOpen:"swing", 
			openedSymbol: "+",
			closedSymbol: "-" 	
		});			

			if ($(window).scrollTop() > 200) {
			  $('.fixed-top').addClass('menu-bg');
		  } else {
			  $('.fixed-top').removeClass('menu-bg');
		  }
			$(window).on('scroll', function(){
				if ( $(window).scrollTop() > 70 ) {
					$('.site-navigation, .header-white, .header').addClass('navbar-fixed');
				} else {
					$('.site-navigation, .header-white, .header').removeClass('navbar-fixed');
				}
			});		  	
		/*END MENU JS*/		

		/*START COUNUDOWN JS*/		
		$('[data-countdown]').each(function() {
			var $this = $(this),
				finalDate = $(this).data('countdown');
			$this.countdown(finalDate, function(event) {
				$this.html(event.strftime('<span class="cdown days"><span class="time-count">%-D</span> <p>Days</p></span> <span class="cdown hour"><span class="time-count">%-H</span> <p>Hours</p></span> <span class="cdown minutes"><span class="time-count">%M</span> <p>Minutes</p></span> <span class="cdown second"> <span><span class="time-count">%S</span> <p>Seconds</p></span>'));
			});
		});	
		/*END COUNUDOWN JS*/				

		/*START VIDEO JS*/
		$('.video_btn').magnificPopup({
            type: 'iframe'
        });
		/*END VIDEO JS*/			

		/*START TESTIMONIAL*/
		 $("#roadmap-slider").owlCarousel({
			items:4,
			itemsDesktop:[1000,4],
			itemsDesktopSmall:[979,2],
			itemsTablet:[768,2],
			itemsMobile:[650,1],
			pagination:true,
			autoPlay:false
		});
		/*END TESTIMONIAL*/			
		
	}); 	
	
	/*START WOW ANIMATION JS*/
	  new WOW().init();	
	/*END WOW ANIMATION JS*/	
				
})(jQuery);


  

