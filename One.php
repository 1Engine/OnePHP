<?php

new One('{
	"api": {
		"domain": "api.",
		"route": {

		}
	},
	"web": {
		"route": {

		}
	},
	"cli": {
		"helpOnError": true,
		"about": "Test %red%cli%clear% example",
		"command": {
			"time": {"description": "Current time %grey,italic%(format)","params": {
				"micro": {"alias": ["-m","--micro"], "filter": "time", "params": "micro"},
				"full": {"alias": ["-f","--full"], "filter": "time", "params": "full"}}
		}
	},
	"language": {
		"default": "en"
	},
	"string": {
		"Title": {"ru": "Заголовок", "en": "Title"}
	}
}');

class One {

	private $settings = [];

	function __construct() {
		// get from params
		// check is cli
		// run method
		// no settings - show error	
	}

	function method($name, $params = []) {
		if (method_exists($this, $name)) {
			$this->{$name}($params);
		}
	}

	// Main

	function cli() {
		// checked
		// error handling
	}

	function api() {
		// checked
		// error handling
	}

	function web() {
		// create site from views
		// error handling
	}

	// Methods

	function echo($params = []) {
		// checked
	}

	function localize($params = []) {
		// checked
	}

	function parse($params = []) {
		// checked with additions
	}

	function zip($params = []) {
		// checked
	}

	function response($params = []) {
		// checked
	}

	function route($params = []) {

	}

	function filter($params = []) {
		if (isset($params['name'])) {
			{$params['name']}($params['params']);
		}
		function trim() {

		}
		function escape() {

		}
		function replace() {

		}
		function route() {

		}
		function url() {

		}
	}

	function check($params = []) {

	}

	function convert($params = []) {
		// video
		// sound
		// image
	}

	function storage($params = []) {
		// checked
	}

	function db($params = []) {
		// json db
		// sql db
		// nosql db
	}

	function crypto($params = []) {
		// checked
	}

	function run($params = []) {
		$command = isset($params['command']) ? $params['command'] : (is_string($params) ? $params : '');
		return shell_exec($command);
	}

	function mail($params = []) {
		// checked
		// setup smtp server
	}

	// Format

	function xml($params = []) {
		// checked
	}

	function json($params = []) {
		// checked
	}

	function yaml($params = []) {
		// checked
	}

	function html($params = []) {
		// checked
	}

	function minimize($params = []) {
		// xml, json, html, js, css, yaml
	}

	// Network

	function request($params = []) {
		// curl method
	}

	function stream($params = []) {
		// stream video
	}

	function websocket($params = []) {
		// persistent connection
	}

	// Maintanance

	function speed($start = false) {
		if (!$start && isset($this->settings['speed']['start'])) {
			if (!isset($this->settings['speed']['check'])) {
				$this->settings['speed']['check'] = [];
			}
			$time = microtime(true) - $this->settings['speed']['start'];
			$this->settings['speed']['check'] []= $time;
			return $time;
		} else {
			$this->settings['speed'] = ['start' => microtime(true)];
		}
	}

	function log($message) {
		// log to variable, screen, syslog, remote server, file, db
	}

}