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
}() );
