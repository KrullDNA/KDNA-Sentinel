/**
 * KDNA Sentinel — admin scripts.
 * Loaded only on Sentinel admin screens.
 */
( function () {
	'use strict';

	document.addEventListener( 'click', function ( event ) {
		var link = event.target.closest ? event.target.closest( '.kdna-preview-toggle' ) : null;
		if ( ! link ) {
			return;
		}
		event.preventDefault();
		var id = link.getAttribute( 'data-item' );
		var panel = document.getElementById( 'kdna-preview-' + id );
		if ( panel ) {
			panel.style.display = ( panel.style.display === 'none' || ! panel.style.display ) ? 'block' : 'none';
		}
	} );

	/*
	 * Tag picker: progressively enhances a <select multiple> into a Select2-style
	 * token field — search, click to add a removable chip, repeat. The native
	 * <select> stays in the DOM (hidden) and remains the source of truth for form
	 * submission, so with JS off the plain multi-select still works.
	 */
	function enhanceTagSelect( select ) {
		var options     = Array.prototype.slice.call( select.options );
		var placeholder = select.getAttribute( 'data-placeholder' ) || 'Type to search…';
		var activeIndex = -1;
		var current     = []; // menu items currently shown

		var wrap  = document.createElement( 'div' );
		wrap.className = 'kdna-tags';
		var chips = document.createElement( 'div' );
		chips.className = 'kdna-tags__chips';
		var input = document.createElement( 'input' );
		input.type = 'text';
		input.className = 'kdna-tags__input';
		input.setAttribute( 'placeholder', placeholder );
		input.setAttribute( 'autocomplete', 'off' );
		var menu = document.createElement( 'div' );
		menu.className = 'kdna-tags__menu';
		menu.hidden = true;

		// Hide the native control but keep it for submission.
		select.classList.add( 'kdna-tags__native' );
		select.setAttribute( 'aria-hidden', 'true' );
		select.tabIndex = -1;
		select.parentNode.insertBefore( wrap, select );
		wrap.appendChild( chips );
		wrap.appendChild( input );
		wrap.appendChild( menu );
		wrap.appendChild( select );

		function selected() {
			return options.filter( function ( o ) { return o.selected; } );
		}

		function renderChips() {
			chips.innerHTML = '';
			selected().forEach( function ( o ) {
				var chip = document.createElement( 'span' );
				chip.className = 'kdna-tags__chip';
				chip.appendChild( document.createTextNode( o.text.trim() ) );
				var x = document.createElement( 'button' );
				x.type = 'button';
				x.className = 'kdna-tags__x';
				x.setAttribute( 'aria-label', 'Remove ' + o.text.trim() );
				x.innerHTML = '&times;';
				x.addEventListener( 'click', function () {
					o.selected = false;
					renderChips();
					renderMenu();
					input.focus();
				} );
				chip.appendChild( x );
				chips.appendChild( chip );
			} );
		}

		function highlight() {
			Array.prototype.slice.call( menu.children ).forEach( function ( el, i ) {
				el.classList.toggle( 'is-active', i === activeIndex );
			} );
		}

		function renderMenu() {
			var q = input.value.trim().toLowerCase();
			menu.innerHTML = '';
			activeIndex = -1;
			current = options.filter( function ( o ) {
				return ! o.selected && ( q === '' || o.text.toLowerCase().indexOf( q ) !== -1 );
			} ).slice( 0, 60 );

			if ( ! current.length ) {
				menu.hidden = true;
				return;
			}

			current.forEach( function ( o ) {
				var item = document.createElement( 'div' );
				item.className = 'kdna-tags__item';
				item.textContent = o.text.trim();
				item.addEventListener( 'mousedown', function ( e ) {
					e.preventDefault();
					o.selected = true;
					input.value = '';
					renderChips();
					renderMenu();
					input.focus();
				} );
				menu.appendChild( item );
			} );
			menu.hidden = false;
		}

		input.addEventListener( 'input', renderMenu );
		input.addEventListener( 'focus', renderMenu );
		input.addEventListener( 'blur', function () {
			window.setTimeout( function () { menu.hidden = true; }, 150 );
		} );
		input.addEventListener( 'keydown', function ( e ) {
			if ( e.key === 'ArrowDown' && ! menu.hidden ) {
				e.preventDefault();
				activeIndex = Math.min( activeIndex + 1, current.length - 1 );
				highlight();
			} else if ( e.key === 'ArrowUp' && ! menu.hidden ) {
				e.preventDefault();
				activeIndex = Math.max( activeIndex - 1, 0 );
				highlight();
			} else if ( e.key === 'Enter' && activeIndex > -1 && current[ activeIndex ] ) {
				e.preventDefault();
				current[ activeIndex ].selected = true;
				input.value = '';
				renderChips();
				renderMenu();
			} else if ( e.key === 'Escape' ) {
				menu.hidden = true;
			} else if ( e.key === 'Backspace' && input.value === '' ) {
				var sel = selected();
				if ( sel.length ) {
					sel[ sel.length - 1 ].selected = false;
					renderChips();
					renderMenu();
				}
			}
		} );

		renderChips();
	}

	document.addEventListener( 'DOMContentLoaded', function () {
		Array.prototype.slice.call(
			document.querySelectorAll( 'select[multiple].kdna-tags-enhance' )
		).forEach( enhanceTagSelect );
	} );
}() );
