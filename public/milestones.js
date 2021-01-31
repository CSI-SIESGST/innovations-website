/*jQuery Milestone Plugin 1.0.0 (works with jQuery 1.10+)*/
(function ($) {
	'use strict',
		($.fn.milestones = function (options) {
			/*Default settings*/
			var settings = $.extend(
				{
					labels: ['Step1', 'Step2', 'Step3', 'Step4'], // Array of labels for each milestone
					stage: 2, //
					checks: 2,
					checkclass: 'checkmark'
				},
				options
			);

			return this.each(function () {
				/*Establish global variables*/
				var id = $(this).attr('id');
				var labels =
					$(this).data('labels') != undefined
						? $(this).data('labels')
						: settings.labels;
				var stage =
					$(this).data('stage') != undefined
						? $(this).data('stage') - 1
						: settings.stage - 1;
				var checks =
					$(this).data('checks') != undefined
						? $(this).data('checks') - 1
						: settings.checks - 1;
				var checkclass =
					$(this).data('checkclass') != undefined
						? $(this).data('checkclass')
						: settings.checkclass;

				/*Set variables based on globals*/
				var ticks = labels.length;
				var div = ticks - 1;
				var per = 100 / div;
				var len = stage * per;

				/*Insert the Milestone components*/
				$(this).html(
					'<div class="progress"><div class="progress-bar" role="progressbar" style="width:' +
						len +
						'%"> </div></div><div class="stage"></div><div class="labels"></div><div class="alt-label">Next Action: <span>' +
						labels[stage] +
						'</span></div>'
				);

				/*Iterate to define the tickmarks and checkmarks*/
				for (x = 0; x <= div; x++) {
					var lft = per * x - 0.4;
					if (x <= checks) {
						var icon =
							'<i class="fa fa-check ' + checkclass + '"></i>';
						var cls = ' past';
					} else {
						var icon = '';
						var cls = ' forward';
					}
					if (x == 0) {
						$('#' + id + ' .stage').append(
							'<span class="tick first' +
								cls +
								'">' +
								icon +
								'</span>'
						);
						$('#' + id + ' .labels').append(
							'<label class="tick-label first"><span>' +
								labels[x] +
								'</span></label>'
						);
					} else if (x == div) {
						$('#' + id + ' .stage').append(
							'<span class="tick last' +
								cls +
								'">' +
								icon +
								'</span>'
						);
						$('#' + id + ' .labels').append(
							'<label class="tick-label last"><span>' +
								labels[x] +
								'</span></label>'
						);
					} else {
						var n = labels[x].length / 5;
						var llft = per * x - n;
						$('#' + id + ' .stage').append(
							'<span class="tick' +
								cls +
								'" style="left:' +
								lft +
								'%">' +
								icon +
								'</span>'
						);
						$('#' + id + ' .labels').append(
							'<label class="tick-label" style="left:' +
								llft +
								'%"><span>' +
								labels[x] +
								'</span></label>'
						);
					}
				}
			});
		});
})(jQuery);
