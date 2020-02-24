<?php
/*
 * One Engine PHP, v.0.1, 2020, created by R
 *
 * Usage from PHP file: 
 * new One('settings_file.json');
 * new One('settings_file.json', 'settings_file.local.json');
 * new One(['settings_file.yaml', 'settings_file.local.xml']);
 * new One('{"settings": {}}');
 * new One(["settings" => []]);
 * new One("http://server/settings.json");
 * 
 * Usage from command line:
 * php One.php /path/settings.json
 */

/*
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
		"about": "Test {{red}}cli{{clear}} example",
		"command": {
			"time": {"description": "Current time {{grey,italic}}(format)","params": {
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
*/

if (count($argv) > 0) {
	new One(array_slice($argv, 1));
}

class One {

	private $settings = [
		'environment' => 'debug'
	];

	function __construct() {
		$this->settings['method'] = [

			// Main
			'start' => function() {
				if (php_sapi_name() === 'cli') {
					$this->method('cli');
				} else {
					if (isset($this->settings['api'])) {
						if (isset($this->settings['api']['domain'])) {
							if (preg_match('{^' . $this->settings['api']['domain'] . '}', $_SERVER['HTTP_HOST'])) {
								$this->method('api');
							}
						} else if (!isset($this->settings['web'])) {
							$this->method('api');
						}
					}
					if (isset($this->settings['web'])) {
						$this->method('web');
					} else {
						throw new Exception('web settings not specified', 10203);
					}
				}
			},
			'cli' => function() {
				$this->settings['error'] = function($e) {
					if (isset($this->settings['method']['error.cli'])) {
						$this->method('error.cli', $e);
					} else {
					}
				};
				// show help on error
			},
			'web' => function() {
				$this->settings['error'] = function($e) {
					if (isset($this->settings['method']['error.web'])) {
						$this->method('error.web', $e);
					} else {
						http_response_code(($code = $e->getCode()) < 1000 ? $code : 500);
					}
				};
				if ($routes = $this->value('route')) {
					$this->method('route', $routes);
				} else { throw new Exception('routes not specified', 40201);}
			},
			'api' => function() {
				$this->settings['error'] = function($e) {
					if (isset($this->settings['method']['error.api'])) {
						$this->method('error.api', $e);
					} else {
						http_response_code(($code = $e->getCode()) < 1000 ? $code : 500);
						$response = ['error' => ['reason' => $e->getMessage(), 'code' => $e->getCode()]];
						if ($this->value('environment') == 'debug') {
							$response['error']['trace'] = $e->getTrace();
						}
						echo json_encode($response);
					}
				};
				if ($routes = $this->value('route')) {
					$this->method('route', $routes);
				} else { throw new Exception('routes not specified', 40201);}
			},

			// Run

			'method' => function($params) {
				if (is_string($params)) {
					if (is_callable($this->settings['method'][$name])) {
						return $this->settings['method'][$params]();
					} else { throw new Exception('method "' . $params . '" not found', 10101);}
				} else if (isset($params['name'])) {
					if (is_callable($this->settings['method'][$name])) {
						if (isset($params['params'])) {
							return $this->settings['method'][$params['name']]($params['params']);
						} else {
							return $this->settings['method'][$params['name']]();
						}
					} else { throw new Exception('method "' . $params['name'] . '" not found', 10101);}
				}
				throw new Exception('wrong method parameters', 10103);
			},
			'run' => function($params) {
				$command = isset($params['command']) ? $params['command'] : (is_string($params) ? $params : '');
				return shell_exec($command);
			},
			'call' => function($params) {
				if (isset($params['name'])) {
					$name = $params['name'];
					$params = isset($params['params']) ? $params['params'] : [];
					if (isset($params['object'])) {
						return call_user_method_array($name, $params['object'], $params);
					} else if (isset($params['class'])) {
						return call_user_func_array($params['class'] . '::' . $name, $params);
					} else {
						return call_user_func_array($name, $params);
					}
				}
				throw new Exception('wrong method parameters', 10103);
			},

			// Crypto

			'crypto.md5' => function($string) {
				return md5($string);
			},
			'crypto.sha1' => function($string) {
				return sha1($string);
			},
			'crypto.sha256' => function($string) {
				return hash('sha256', $string);
			},
			'crypto.sha512' => function($string) {
				return hash('sha512', $string);
			},
			'crypto.blowfish' => function($string, $salt = null) {
				if (CRYPT_BLOWFISH == 1) {
					if (is_null($salt)) {
						$salt = '$2y$08$' . str_repeat('0', 22) . '$';
					}
		 		   	return crypt($text, $salt);
				}
			},
			'crypto.base64Encode' => function($string) {
				return base64_encode($string);
			},
			'crypto.base64Decode' => function($string) {
				return base64_decode($string);
			},
			'crypto.crc32' => function($string) {
				return sprintf("%u", crc32($string));
			},
			'crypto.crc32File' => function($path) {
				return hash_file("CRC32", $path);
			},
			'crypto.hash' => function($string, $algorithm = 'sha512') {
				return hash($algorithm, $string);
			},
			'crypto.uuid' => function() {
		    	if (function_exists('com_create_guid') === true) {
		        	return trim(com_create_guid(), '{}');
		    	}
			    $data = openssl_random_pseudo_bytes(16);
			    $data[6] = chr(ord($data[6]) & 0x0f | 0x40); // set version to 0100
			    $data[8] = chr(ord($data[8]) & 0x3f | 0x80); // set bits 6-7 to 10
			    return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
			},

			// Format

			'format.xml.parse' => function($params) {
				if ($attributes) {
					function xml2Array(\SimpleXMLElement $parent) {
		    			$array = [];
		    			foreach ($parent as $name => $element) {
		    				if (is_numeric($number = str_replace('Item', '', $name))) {
		    					$name = $number;
		    				}
		        			($node = & $array[$name]) && (count($node) === 1 ? $node = [$node] : 1) && $node = & $node[];
		        			$node = $element->count() ? XML2Array($element) : trim($element);
		    			}
		    			return $array;
					}
					$xml = simplexml_load_string($content);
					return [$xml->getName() => xml2Array($xml)];
				} else {
					$xml = simplexml_load_string($content);
					return [$xml->getName() => json_decode(json_encode((array) $xml), true)];
				}
			},
			'format.xml.create' => function($params = []) {
				$content = isset($params['content']) ? $params['content'] : '';
				$root = isset($params['root']) ? $params['root'] : 'root';
				function array2xml($data, &$xml) {
				    foreach ($data as $key => $value) {
				        if (is_numeric($key)) {
				            $key = 'Item' . $key;
				        }
				        if (is_array($value)) {
				            $subnode = $xml->addChild($key);
				            array2xml($value, $subnode);
				        } else {
				            $xml->addChild($key, htmlspecialchars($value));
				        }
				     }
				}
				$xml = new \SimpleXMLElement("<$root/>");
				array2xml($content, $xml);
				return $xml->asXML();
			},
			'format.html.parse' => function($params) {

			},
			'format.html.create' => function($params) {

			},
			'format.json.parse' => function($params) {
				return json_decode($params, true);
			},			
			'format.json.create' => function($params) {
				return json_encode($params);
			},
			'format.yaml.parse' => function($params) {
				return \sfYaml::load($params);
			},
			'format.yaml.create' => function($params) {
				return \sfYaml::dump($params);
			},

			// Parse

			'parse' => function($params) {

			},
			'parse.html' => function($params) {
			},
			'parse.html.images' => function($params) {

			},
			'parse.html.videos' => function($params) {

			},
			'parse.html.text' => function($params) {

			},
			'parse.html.links' => function($params) {

			},

			// Localize

			'localize' => function($params) {

			},

			// Archive

			'archive.gzipText' => function($text, $level = 3, $file = null) {
				$text = gzencode((string) $text, $level);
				if (!is_null($file)) {
					$fp = fopen($file, "w");
					fwrite($fp, $text);
					fclose($fp);
				}
			},
			'archive.gunzipText' => function($text) {
				return gzdecode($text);
			},
			'archive.gunzipTextFromFile' => function($file) {
			    $string = "";
			    if (file_exists($file)) {
				    $fp = gzopen($file, "rb");
			    	while (!gzeof($fp)) {
			        	$string .= gzread($fp, 4096);
			    	}
			    	gzclose($fp);
			    }
		    	return $string;
			},
			'archive.gzip' => function($path) {
				return $this->settings['method']['run']("gzip $path");
			},
			'archive.gunzip' => function($path) {
				return $this->settings['method']['run']("gunzip $path");
			},
			'archive.tar' => function($name, $path) {
				return $this->settings['method']['run']("tar -cvf $name $path");
			},
			'archive.untar' => function($path) {
				return $this->settings['method']['run']("tar -xvf $path");
			},
			'archive.targz' => function($name, $path) {
				return $this->settings['method']['run']("tar -czvf $name $path");
			},
			'archive.untargz' => function($path) {
				return $this->settings['method']['run']("tar -xzvf $path");
			},
			'archive.zip' => function($params) {
				return $this->settings['method']['run']('zip ' . $params['name'] . '.zip ' . $params['path']);
			},
			'archive.unzip' => function($path) {
				return $this->settings['method']['run']("unzip $path");
			},
			'archive.unrar' => function($path) {
				return $this->settings['method']['run']("unrar x $path");
			},

			// CLI
			
			'echo' => function($params = null) {
				if (is_string($params)) {
					echo $params;
				} else if (is_array($params)) {
					var_export($params);
				}
			},


			// Route

			'route.parse' => function($params = []) {

			},
			'route.create' => function() {

			},

			// Filter

			'string.trim' => function($params) {
				return trim($params);
			},
			'string.escape' => function() {

			},
			'string.replace' => function() {

			},
			'string.url' => function() {

			},

			// Check

			'check.double' => function($params = []) {

			},
			'check.int' => function($params = []) {

			},
			'check.bool' => function($params = []) {

			},
			'check.string' => function($params = []) {

			},
			'check.date' => function($params = []) {

			},

			// Convert

			'convert.image' => function($params = []) {
			},
			'convert.video' => function($params = []) {
			},
			'convert.sound' => function($params = []) {
			},

			// DB

			'db.connect' => function($params = []) {
			},
			'db.get' => function($params = []) {
				// json db
				// sql db
				// nosql db
			},
			'db.set' => function($params = []) {
			},

			// Mail

			'mail.send' => function($params = []) {
				// checked
				// setup smtp server
			},

			// Minimize
			'minimize.xml' => function($params = []) {
			},
			'minimize.json' => function($params = []) {
			},
			'minimize.js' => function($params = []) {
			},
			'minimize.css' => function($params = []) {
			},
			'minimize.yaml' => function($params = []) {
			},
			'minimize.html' => function($params = []) {
			},
			
			// Network
			
			'network.request' => function($params = []) {
				// curl method
			},
			'network.stream' => function($params = []) {
				// stream video
			},
			'network.websocket' => function($params = []) {
				// persistent connection
			},
			'network.response' => function($params) {

			},
			'network.ftp' => function($params) {

			},

			// File

			'file.get' => function($params = []) {
				return file_get_contents($params);
			},
			'file.set' => function($params = []) {
				return file_put_contents($params['path'], $params['content']);
			},
			'file.exists' => function($params = []) {
				return file_exists($params['path']);
			},
			'file.remove' => function($path) {
				if (!(is_string($path) && strlen($path) > 1)) { return; }
				function remove($path) {
					if (is_dir($path)) { 
				    	$objects = scandir($path);
				     	foreach ($objects as $object) { 
				       		if ($object != '.' && $object != '..') { 
				         		if (is_dir($path.DIRECTORY_SEPARATOR.$object) && !is_link($path.DIRECTORY_SEPARATOR.$object)) {
				           			remove($path.DIRECTORY_SEPARATOR.$object);
				         		} else {
				           			unlink($path.DIRECTORY_SEPARATOR.$object); 
				           		}
				           	}
				       	}
					    rmdir($path); 
				    } else if (file_exists($path)) {
				    	unlink($path);
				    }
				}
				remove($path);
			},
			'file.copy' => function($params = []) {
				if (isset($params['from']) && isset($params['to'])) {

				}
			},
			'file.move' => function($params = []) {
				if (isset($params['from']) && isset($params['to'])) {
					
				}
			},
			'file.attributes' => function($params = []) {
				if (isset($params['path'])) {
					
				}
			},

			// Error

			'error' => null,

			// Maintanance

			'speed' => function($start = false) {
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
			},
			'log' => function($message) {
				// log to variable, screen, syslog, remote server, file, db
			},
			'settings.set' => function($params) {
				array_replace_recursive($this->settings, $params);
			},
			'settings.get' => function($params) {

			},

			// AWS

			'aws.ec2.list' => function() {

			},
			'aws.ec2.start' => function() {

			},
			'aws.ec2.stop' => function() {

			},
			'aws.ec2.pause' => function() {

			},
			'aws.s3.bucket.list' => function() {

			},
			'aws.s3.bucket.create' => function() {

			},
			'aws.s3.file.get' => function() {

			},
			'aws.s3.file.create' => function() {

			},
			'aws.s3.file.remove' => function() {

			},
			'aws.cloudFront.file.get' => function() {

			},
			'aws.cloudFront.file.create' => function() {

			},
			'aws.cloudFront.file.remove' => function() {

			},
			'aws.dynamoDB.list' => function() {

			},
			'aws.dynamoDB.create' => function() {

			},
			'aws.dynamoDB.remove' => function() {

			},
			'aws.dynamoDB.get' => function() {

			},
			'aws.dynamoDB.set' => function() {

			},
			'aws.lambda.list' => function() {

			},
			'aws.lambda.get' => function() {

			},
			'aws.lambda.create' => function() {

			},
			'aws.lambda.remove' => function() {

			},
			'aws.route53' => function() {

			}

			// Azure
		];

		try {
			if (func_num_args() > 0) {
				if (count($settings = $this->settings(func_get_args())) == 0) {
					throw new Exception('settings not loaded', 10201);
				}
				$this->settings = array_replace_recursive($this->settings, $settings);
				$this->method('start');
			}
		} catch (Exception $e) {
			if (isset($this->settings['error']) && is_callable($this->settings['error'])) {
				$this->settings['error']($e);
			} else {
				if (!($cli = php_sapi_name() == 'cli')) { echo '<pre>';}
				echo $e->getMessage() . PHP_EOL;
	 			if ($this->value('environment') == 'debug') {
					echo $e->getTraceAsString() . PHP_EOL;
				}
				if (!$cli) { echo '</pre>';}
			}
		}
	}

	function settings($params, $settings = []) {
		if (is_string($params)) {
			$settingsWithCheck = function($settingsNew) use (&$settings) {
				if (is_array($settingsNew)) {
					return array_replace_recursive($settings, $settingsNew);
				} else { throw new Exception('wrong settings format', 10202);}
			};
			if (strpos($params, '{') === 0) {
				$settings = $settingsWithCheck($this->method('format.json.parse', $params));
			} else {
				preg_match('/\.(json|yaml|xml)$/', $params, $matches);
				$format = isset($matches[1]) ? $matches[1] : false;
				if (preg_match('/^(http|https|ftp)\:\/\//', $params, $matches)) {
					if ($matches[1] != 'ftp') {
						$content = $this->method('request', $params);
					} else {
						$content = $this->method('ftp', $params);
					}
				} else if ($format && $this->method('file.exists', $params)) {
					$content = $this->method('file.get', $params);
				} else {
					$content = $params;
				}
				switch ($format) {
					case 'json': $settings = $settingsWithCheck($this->method('format.json.parse', $content)); break;
					case 'yaml': $settings = $settingsWithCheck($this->method('format.yaml.parse', $content)); break;
					case 'xml': $settings = $settingsWithCheck($this->method('format.xml.parse', $content)); break;
					default: $settings = $settingsWithCheck($this->method('format.json.parse', $content));
				}
			}
		} else if (is_array($params)) {
			if (array_keys($params) === range(0, count($params) - 1)) {
				foreach ($params as $param) {
					$settings = array_replace_recursive($settings, $this->settings($param));
				}
			} else {
				$settings = array_replace_recursive($settings, $params);
			}
		}
		return $settings;
	}

	function method($name, $params = null) {
		if (isset($this->settings['method'][$name])) {
			return $this->settings['method'][$name]($params);
		} else { throw new Exception('method "' . $name . '" not found', 10101);}
	}

	function value($params) {
		if (isset($this->settings[$params])) {
			return $this->settings[$params];
		}
	}
}

/// Classes

private class sfYaml {

  static protected $spec = '1.2';
  
  static public function setSpecVersion($version) {
    if (!in_array($version, array('1.1', '1.2'))) {
      throw new InvalidArgumentException(sprintf('Version %s of the YAML specifications is not supported', $version));
    }
    self::$spec = $version;
  }

  static public function getSpecVersion() {
    return self::$spec;
  }

  public static function load($input) {
    $file = '';
    if (strpos($input, "\n") === false && is_file($input)) {
      $file = $input;
      ob_start();
      $retval = include($input);
      $content = ob_get_clean();
      $input = is_array($retval) ? $retval : $content;
    }
    if (is_array($input)) {
      return $input;
    }
    require_once dirname(__FILE__).'/sfYamlParser.php';
    $yaml = new sfYamlParser();
    try {
      $ret = $yaml->parse($input);
    } catch (Exception $e) {
      throw new InvalidArgumentException(sprintf('Unable to parse %s: %s', $file ? sprintf('file "%s"', $file) : 'string', $e->getMessage()));
    }
    return $ret;
  }

  public static function dump($array, $inline = 2) {
    require_once dirname(__FILE__).'/sfYamlDumper.php';
    $yaml = new sfYamlDumper();
    return $yaml->dump($array, $inline);
  }
}

private class sfYamlDumper {
  
  public function dump($input, $inline = 0, $indent = 0) {
    $output = '';
    $prefix = $indent ? str_repeat(' ', $indent) : '';
    if ($inline <= 0 || !is_array($input) || empty($input)) {
      $output .= $prefix.sfYamlInline::dump($input);
    } else {
      $isAHash = array_keys($input) !== range(0, count($input) - 1);
      foreach ($input as $key => $value) {
        $willBeInlined = $inline - 1 <= 0 || !is_array($value) || empty($value);
        $output .= sprintf('%s%s%s%s',
          $prefix,
          $isAHash ? sfYamlInline::dump($key).':' : '-',
          $willBeInlined ? ' ' : "\n",
          $this->dump($value, $inline - 1, $willBeInlined ? 0 : $indent + 2)
        ).($willBeInlined ? "\n" : '');
      }
    }
    return $output;
  }
}

private class sfYamlInline {
  const REGEX_QUOTED_STRING = '(?:"([^"\\\\]*(?:\\\\.[^"\\\\]*)*)"|\'([^\']*(?:\'\'[^\']*)*)\')';
  static public function load($value) {
    $value = trim($value);
    if (0 == strlen($value)) {
      return '';
    }
    if (function_exists('mb_internal_encoding') && ((int) ini_get('mbstring.func_overload')) & 2) {
      $mbEncoding = mb_internal_encoding();
      mb_internal_encoding('ASCII');
    }
    switch ($value[0]) {
      case '[':
        $result = self::parseSequence($value);
        break;
      case '{':
        $result = self::parseMapping($value);
        break;
      default:
        $result = self::parseScalar($value);
    }
    if (isset($mbEncoding)) {
      mb_internal_encoding($mbEncoding);
    }
    return $result;
  }

  static public function dump($value) {
    if ('1.1' === sfYaml::getSpecVersion()) {
      $trueValues = array('true', 'on', '+', 'yes', 'y');
      $falseValues = array('false', 'off', '-', 'no', 'n');
    } else {
      $trueValues = array('true');
      $falseValues = array('false');
    }
    switch (true) {
      case is_resource($value):
        throw new InvalidArgumentException('Unable to dump PHP resources in a YAML file.');
      case is_object($value):
        return '!!php/object:'.serialize($value);
      case is_array($value):
        return self::dumpArray($value);
      case null === $value:
        return 'null';
      case true === $value:
        return 'true';
      case false === $value:
        return 'false';
      case ctype_digit($value):
        return is_string($value) ? "'$value'" : (int) $value;
      case is_numeric($value):
        return is_infinite($value) ? str_ireplace('INF', '.Inf', strval($value)) : (is_string($value) ? "'$value'" : $value);
      case false !== strpos($value, "\n") || false !== strpos($value, "\r"):
        return sprintf('"%s"', str_replace(array('"', "\n", "\r"), array('\\"', '\n', '\r'), $value));
      case preg_match('/[ \s \' " \: \{ \} \[ \] , & \* \# \?] | \A[ - ? | < > = ! % @ ` ]/x', $value):
        return sprintf("'%s'", str_replace('\'', '\'\'', $value));
      case '' == $value:
        return "''";
      case preg_match(self::getTimestampRegex(), $value):
        return "'$value'";
      case in_array(strtolower($value), $trueValues):
        return "'$value'";
      case in_array(strtolower($value), $falseValues):
        return "'$value'";
      case in_array(strtolower($value), array('null', '~')):
        return "'$value'";
      default:
        return $value;
    }
  }

  static protected function dumpArray($value) {
    $keys = array_keys($value);
    if (
      (1 == count($keys) && '0' == $keys[0])
      ||
      (count($keys) > 1 && array_reduce($keys, create_function('$v,$w', 'return (integer) $v + (integer) $w;'), 0) == count($keys) * (count($keys) - 1) / 2)) {
      $output = array();
      foreach ($value as $val) {
        $output[] = self::dump($val);
      }
      return sprintf('[%s]', implode(', ', $output));
    }
    $output = array();
    foreach ($value as $key => $val) {
      $output[] = sprintf('%s: %s', self::dump($key), self::dump($val));
    }
    return sprintf('{ %s }', implode(', ', $output));
  }

  static public function parseScalar($scalar, $delimiters = null, $stringDelimiters = array('"', "'"), &$i = 0, $evaluate = true) {
    if (in_array($scalar[$i], $stringDelimiters))
    {
      $output = self::parseQuotedScalar($scalar, $i);
    } else {
      if (!$delimiters) {
        $output = substr($scalar, $i);
        $i += strlen($output);
        if (false !== $strpos = strpos($output, ' #')) {
          $output = rtrim(substr($output, 0, $strpos));
        }
      } else if (preg_match('/^(.+?)('.implode('|', $delimiters).')/', substr($scalar, $i), $match)) {
        $output = $match[1];
        $i += strlen($output);
      } else {
        throw new InvalidArgumentException(sprintf('Malformed inline YAML string (%s).', $scalar));
      }
      $output = $evaluate ? self::evaluateScalar($output) : $output;
    }
    return $output;
  }

  static protected function parseQuotedScalar($scalar, &$i) {
    if (!preg_match('/'.self::REGEX_QUOTED_STRING.'/Au', substr($scalar, $i), $match)) {
      throw new InvalidArgumentException(sprintf('Malformed inline YAML string (%s).', substr($scalar, $i)));
    }
    $output = substr($match[0], 1, strlen($match[0]) - 2);
    if ('"' == $scalar[$i]) {
      $output = str_replace(array('\\"', '\\n', '\\r'), array('"', "\n", "\r"), $output);
    } else {
      $output = str_replace('\'\'', '\'', $output);
    }
    $i += strlen($match[0]);
    return $output;
  }

  static protected function parseSequence($sequence, &$i = 0) {
    $output = array();
    $len = strlen($sequence);
    $i += 1;
    while ($i < $len) {
      switch ($sequence[$i]) {
        case '[':
          $output[] = self::parseSequence($sequence, $i);
          break;
        case '{':
          $output[] = self::parseMapping($sequence, $i);
          break;
        case ']':
          return $output;
        case ',':
        case ' ':
          break;
        default:
          $isQuoted = in_array($sequence[$i], array('"', "'"));
          $value = self::parseScalar($sequence, array(',', ']'), array('"', "'"), $i);
          if (!$isQuoted && false !== strpos($value, ': ')) {
            try {
              $value = self::parseMapping('{'.$value.'}');
            } catch (InvalidArgumentException $e) {}
          }
          $output[] = $value;
          --$i;
      }
      ++$i;
    }
    throw new InvalidArgumentException(sprintf('Malformed inline YAML string %s', $sequence));
  }

  static protected function parseMapping($mapping, &$i = 0) {
    $output = array();
    $len = strlen($mapping);
    $i += 1;
    while ($i < $len) {
      switch ($mapping[$i]) {
        case ' ':
        case ',':
          ++$i;
          continue 2;
        case '}':
          return $output;
      }
      $key = self::parseScalar($mapping, array(':', ' '), array('"', "'"), $i, false);
      $done = false;
      while ($i < $len) {
        switch ($mapping[$i]) {
          case '[':
            $output[$key] = self::parseSequence($mapping, $i);
            $done = true;
            break;
          case '{':
            $output[$key] = self::parseMapping($mapping, $i);
            $done = true;
            break;
          case ':':
          case ' ':
            break;
          default:
            $output[$key] = self::parseScalar($mapping, array(',', '}'), array('"', "'"), $i);
            $done = true;
            --$i;
        }
        ++$i;
        if ($done) {
          continue 2;
        }
      }
    }
    throw new InvalidArgumentException(sprintf('Malformed inline YAML string %s', $mapping));
  }

  static protected function evaluateScalar($scalar) {
    $scalar = trim($scalar);
    if ('1.1' === sfYaml::getSpecVersion()) {
      $trueValues = array('true', 'on', '+', 'yes', 'y');
      $falseValues = array('false', 'off', '-', 'no', 'n');
    } else {
      $trueValues = array('true');
      $falseValues = array('false');
    }
    switch (true) {
      case 'null' == strtolower($scalar):
      case '' == $scalar:
      case '~' == $scalar:
        return null;
      case 0 === strpos($scalar, '!str'):
        return (string) substr($scalar, 5);
      case 0 === strpos($scalar, '! '):
        return intval(self::parseScalar(substr($scalar, 2)));
      case 0 === strpos($scalar, '!!php/object:'):
        return unserialize(substr($scalar, 13));
      case ctype_digit($scalar):
        $raw = $scalar;
        $cast = intval($scalar);
        return '0' == $scalar[0] ? octdec($scalar) : (((string) $raw == (string) $cast) ? $cast : $raw);
      case in_array(strtolower($scalar), $trueValues):
        return true;
      case in_array(strtolower($scalar), $falseValues):
        return false;
      case is_numeric($scalar):
        return '0x' == $scalar[0].$scalar[1] ? hexdec($scalar) : floatval($scalar);
      case 0 == strcasecmp($scalar, '.inf'):
      case 0 == strcasecmp($scalar, '.NaN'):
        return -log(0);
      case 0 == strcasecmp($scalar, '-.inf'):
        return log(0);
      case preg_match('/^(-|\+)?[0-9,]+(\.[0-9]+)?$/', $scalar):
        return floatval(str_replace(',', '', $scalar));
      case preg_match(self::getTimestampRegex(), $scalar):
        return strtotime($scalar);
      default:
        return (string) $scalar;
    }
  }

  static protected function getTimestampRegex() {
    return <<<EOF
    ~^
    (?P<year>[0-9][0-9][0-9][0-9])
    -(?P<month>[0-9][0-9]?)
    -(?P<day>[0-9][0-9]?)
    (?:(?:[Tt]|[ \t]+)
    (?P<hour>[0-9][0-9]?)
    :(?P<minute>[0-9][0-9])
    :(?P<second>[0-9][0-9])
    (?:\.(?P<fraction>[0-9]*))?
    (?:[ \t]*(?P<tz>Z|(?P<tz_sign>[-+])(?P<tz_hour>[0-9][0-9]?)
    (?::(?P<tz_minute>[0-9][0-9]))?))?)?
    $~x
EOF;
  }
}

private class sfYamlParser {
  protected
    $offset        = 0,
    $lines         = array(),
    $currentLineNb = -1,
    $currentLine   = '',
    $refs          = array();

  public function __construct($offset = 0) {
  	if (!defined('PREG_BAD_UTF8_OFFSET_ERROR')) {
	  define('PREG_BAD_UTF8_OFFSET_ERROR', 5);
	}
    $this->offset = $offset;
  }

  public function parse($value)
  {
    $this->currentLineNb = -1;
    $this->currentLine = '';
    $this->lines = explode("\n", $this->cleanup($value));
    if (function_exists('mb_internal_encoding') && ((int) ini_get('mbstring.func_overload')) & 2) {
      $mbEncoding = mb_internal_encoding();
      mb_internal_encoding('UTF-8');
    }
    $data = array();
    while ($this->moveToNextLine()) {
      if ($this->isCurrentLineEmpty()) {
        continue;
      }

      if (preg_match('#^\t+#', $this->currentLine)) {
        throw new InvalidArgumentException(sprintf('A YAML file cannot contain tabs as indentation at line %d (%s).', $this->getRealCurrentLineNb() + 1, $this->currentLine));
      }
      $isRef = $isInPlace = $isProcessed = false;
      if (preg_match('#^\-((?P<leadspaces>\s+)(?P<value>.+?))?\s*$#u', $this->currentLine, $values)) {
        if (isset($values['value']) && preg_match('#^&(?P<ref>[^ ]+) *(?P<value>.*)#u', $values['value'], $matches)) {
          $isRef = $matches['ref'];
          $values['value'] = $matches['value'];
        }
        if (!isset($values['value']) || '' == trim($values['value'], ' ') || 0 === strpos(ltrim($values['value'], ' '), '#')) {
          $c = $this->getRealCurrentLineNb() + 1;
          $parser = new sfYamlParser($c);
          $parser->refs =& $this->refs;
          $data[] = $parser->parse($this->getNextEmbedBlock());
        } else {
          if (isset($values['leadspaces'])
            && ' ' == $values['leadspaces']
            && preg_match('#^(?P<key>'.sfYamlInline::REGEX_QUOTED_STRING.'|[^ \'"\{].*?) *\:(\s+(?P<value>.+?))?\s*$#u', $values['value'], $matches)) {
            $c = $this->getRealCurrentLineNb();
            $parser = new sfYamlParser($c);
            $parser->refs =& $this->refs;
            $block = $values['value'];
            if (!$this->isNextLineIndented()) {
              $block .= "\n".$this->getNextEmbedBlock($this->getCurrentLineIndentation() + 2);
            }
            $data[] = $parser->parse($block);
          } else {
            $data[] = $this->parseValue($values['value']);
          }
        }
      } else if (preg_match('#^(?P<key>'.sfYamlInline::REGEX_QUOTED_STRING.'|[^ \'"].*?) *\:(\s+(?P<value>.+?))?\s*$#u', $this->currentLine, $values))
      {
        $key = sfYamlInline::parseScalar($values['key']);
        if ('<<' === $key) {
          if (isset($values['value']) && '*' === substr($values['value'], 0, 1)) {
            $isInPlace = substr($values['value'], 1);
            if (!array_key_exists($isInPlace, $this->refs)) {
              throw new InvalidArgumentException(sprintf('Reference "%s" does not exist at line %s (%s).', $isInPlace, $this->getRealCurrentLineNb() + 1, $this->currentLine));
            }
          } else {
            if (isset($values['value']) && $values['value'] !== '') {
              $value = $values['value'];
            } else {
              $value = $this->getNextEmbedBlock();
            }
            $c = $this->getRealCurrentLineNb() + 1;
            $parser = new sfYamlParser($c);
            $parser->refs =& $this->refs;
            $parsed = $parser->parse($value);
            $merged = array();
            if (!is_array($parsed)) {
              throw new InvalidArgumentException(sprintf("YAML merge keys used with a scalar value instead of an array at line %s (%s)", $this->getRealCurrentLineNb() + 1, $this->currentLine));
            } else if (isset($parsed[0])) {
              foreach (array_reverse($parsed) as $parsedItem) {
                if (!is_array($parsedItem)) {
                  throw new InvalidArgumentException(sprintf("Merge items must be arrays at line %s (%s).", $this->getRealCurrentLineNb() + 1, $parsedItem));
                }
                $merged = array_merge($parsedItem, $merged);
              }
            } else {
              $merged = array_merge($merged, $parsed);
            }
            $isProcessed = $merged;
          }
        } else if (isset($values['value']) && preg_match('#^&(?P<ref>[^ ]+) *(?P<value>.*)#u', $values['value'], $matches)) {
          $isRef = $matches['ref'];
          $values['value'] = $matches['value'];
        }
        if ($isProcessed) {
          $data = $isProcessed;
        } else if (!isset($values['value']) || '' == trim($values['value'], ' ') || 0 === strpos(ltrim($values['value'], ' '), '#')) {
          if ($this->isNextLineIndented()) {
            $data[$key] = null;
          } else {
            $c = $this->getRealCurrentLineNb() + 1;
            $parser = new sfYamlParser($c);
            $parser->refs =& $this->refs;
            $data[$key] = $parser->parse($this->getNextEmbedBlock());
          }
        } else {
          if ($isInPlace) {
            $data = $this->refs[$isInPlace];
          } else {
            $data[$key] = $this->parseValue($values['value']);
          }
        }
      } else {
        if (2 == count($this->lines) && empty($this->lines[1])) {
          $value = sfYamlInline::load($this->lines[0]);
          if (is_array($value)) {
            $first = reset($value);
            if ('*' === substr($first, 0, 1)) {
              $data = array();
              foreach ($value as $alias)
              {
                $data[] = $this->refs[substr($alias, 1)];
              }
              $value = $data;
            }
          }
          if (isset($mbEncoding)) {
            mb_internal_encoding($mbEncoding);
          }
          return $value;
        }
        switch (preg_last_error()) {
          case PREG_INTERNAL_ERROR:
            $error = 'Internal PCRE error on line';
            break;
          case PREG_BACKTRACK_LIMIT_ERROR:
            $error = 'pcre.backtrack_limit reached on line';
            break;
          case PREG_RECURSION_LIMIT_ERROR:
            $error = 'pcre.recursion_limit reached on line';
            break;
          case PREG_BAD_UTF8_ERROR:
            $error = 'Malformed UTF-8 data on line';
            break;
          case PREG_BAD_UTF8_OFFSET_ERROR:
            $error = 'Offset doesn\'t correspond to the begin of a valid UTF-8 code point on line';
            break;
          default:
            $error = 'Unable to parse line';
        }
        throw new InvalidArgumentException(sprintf('%s %d (%s).', $error, $this->getRealCurrentLineNb() + 1, $this->currentLine));
      }
      if ($isRef) {
        $this->refs[$isRef] = end($data);
      }
    }
    if (isset($mbEncoding)) {
      mb_internal_encoding($mbEncoding);
    }
    return empty($data) ? null : $data;
  }

  protected function getRealCurrentLineNb() {
    return $this->currentLineNb + $this->offset;
  }

  protected function getCurrentLineIndentation() {
    return strlen($this->currentLine) - strlen(ltrim($this->currentLine, ' '));
  }

  protected function getNextEmbedBlock($indentation = null) {
    $this->moveToNextLine();
    if (null === $indentation) {
      $newIndent = $this->getCurrentLineIndentation();
      if (!$this->isCurrentLineEmpty() && 0 == $newIndent) {
        throw new InvalidArgumentException(sprintf('Indentation problem at line %d (%s)', $this->getRealCurrentLineNb() + 1, $this->currentLine));
      }
    } else {
      $newIndent = $indentation;
    }
    $data = array(substr($this->currentLine, $newIndent));
    while ($this->moveToNextLine()) {
      if ($this->isCurrentLineEmpty()) {
        if ($this->isCurrentLineBlank()) {
          $data[] = substr($this->currentLine, $newIndent);
        }
        continue;
      }
      $indent = $this->getCurrentLineIndentation();
      if (preg_match('#^(?P<text> *)$#', $this->currentLine, $match)) {
        $data[] = $match['text'];
      } else if ($indent >= $newIndent) {
        $data[] = substr($this->currentLine, $newIndent);
      } else if (0 == $indent) {
        $this->moveToPreviousLine();
        break;
      } else {
        throw new InvalidArgumentException(sprintf('Indentation problem at line %d (%s)', $this->getRealCurrentLineNb() + 1, $this->currentLine));
      }
    }
    return implode("\n", $data);
  }

  protected function moveToNextLine() {
    if ($this->currentLineNb >= count($this->lines) - 1) {
      return false;
    }
    $this->currentLine = $this->lines[++$this->currentLineNb];
    return true;
  }

  protected function moveToPreviousLine() {
    $this->currentLine = $this->lines[--$this->currentLineNb];
  }

  protected function parseValue($value) {
    if ('*' === substr($value, 0, 1)) {
      if (false !== $pos = strpos($value, '#')) {
        $value = substr($value, 1, $pos - 2);
      } else {
        $value = substr($value, 1);
      }
      if (!array_key_exists($value, $this->refs)) {
        throw new InvalidArgumentException(sprintf('Reference "%s" does not exist (%s).', $value, $this->currentLine));
      }
      return $this->refs[$value];
    }

    if (preg_match('/^(?P<separator>\||>)(?P<modifiers>\+|\-|\d+|\+\d+|\-\d+|\d+\+|\d+\-)?(?P<comments> +#.*)?$/', $value, $matches)) {
      $modifiers = isset($matches['modifiers']) ? $matches['modifiers'] : '';

      return $this->parseFoldedScalar($matches['separator'], preg_replace('#\d+#', '', $modifiers), intval(abs($modifiers)));
    } else {
      return sfYamlInline::load($value);
    }
  }

  protected function parseFoldedScalar($separator, $indicator = '', $indentation = 0) {
    $separator = '|' == $separator ? "\n" : ' ';
    $text = '';
    $notEOF = $this->moveToNextLine();
    while ($notEOF && $this->isCurrentLineBlank()) {
      $text .= "\n";

      $notEOF = $this->moveToNextLine();
    }
    if (!$notEOF) {
      return '';
    }
    if (!preg_match('#^(?P<indent>'.($indentation ? str_repeat(' ', $indentation) : ' +').')(?P<text>.*)$#u', $this->currentLine, $matches)) {
      $this->moveToPreviousLine();
      return '';
    }
    $textIndent = $matches['indent'];
    $previousIndent = 0;
    $text .= $matches['text'].$separator;
    while ($this->currentLineNb + 1 < count($this->lines)) {
      $this->moveToNextLine();
      if (preg_match('#^(?P<indent> {'.strlen($textIndent).',})(?P<text>.+)$#u', $this->currentLine, $matches)) {
        if (' ' == $separator && $previousIndent != $matches['indent']) {
          $text = substr($text, 0, -1)."\n";
        }
        $previousIndent = $matches['indent'];
        $text .= str_repeat(' ', $diff = strlen($matches['indent']) - strlen($textIndent)).$matches['text'].($diff ? "\n" : $separator);
      } else if (preg_match('#^(?P<text> *)$#', $this->currentLine, $matches)) {
        $text .= preg_replace('#^ {1,'.strlen($textIndent).'}#', '', $matches['text'])."\n";
      } else {
        $this->moveToPreviousLine();
        break;
      }
    }
    if (' ' == $separator) {
      $text = preg_replace('/ (\n*)$/', "\n$1", $text);
    }
    switch ($indicator) {
      case '':
        $text = preg_replace('#\n+$#s', "\n", $text);
        break;
      case '+':
        break;
      case '-':
        $text = preg_replace('#\n+$#s', '', $text);
        break;
    }
    return $text;
  }

  protected function isNextLineIndented() {
    $currentIndentation = $this->getCurrentLineIndentation();
    $notEOF = $this->moveToNextLine();
    while ($notEOF && $this->isCurrentLineEmpty()) {
      $notEOF = $this->moveToNextLine();
    }
    if (false === $notEOF) {
      return false;
    }
    $ret = false;
    if ($this->getCurrentLineIndentation() <= $currentIndentation) {
      $ret = true;
    }
    $this->moveToPreviousLine();
    return $ret;
  }

  protected function isCurrentLineEmpty() {
    return $this->isCurrentLineBlank() || $this->isCurrentLineComment();
  }

  protected function isCurrentLineBlank() {
    return '' == trim($this->currentLine, ' ');
  }

  protected function isCurrentLineComment() {
    $ltrimmedLine = ltrim($this->currentLine, ' ');
    return $ltrimmedLine[0] === '#';
  }

  protected function cleanup($value) {
    $value = str_replace(array("\r\n", "\r"), "\n", $value);
    if (!preg_match("#\n$#", $value)) {
      $value .= "\n";
    }
    $count = 0;
    $value = preg_replace('#^\%YAML[: ][\d\.]+.*\n#su', '', $value, -1, $count);
    $this->offset += $count;
    $trimmedValue = preg_replace('#^(\#.*?\n)+#s', '', $value, -1, $count);
    if ($count == 1) {
      $this->offset += substr_count($value, "\n") - substr_count($trimmedValue, "\n");
      $value = $trimmedValue;
    }
    $trimmedValue = preg_replace('#^\-\-\-.*?\n#s', '', $value, -1, $count);
    if ($count == 1) {
      $this->offset += substr_count($value, "\n") - substr_count($trimmedValue, "\n");
      $value = $trimmedValue;
      $value = preg_replace('#\.\.\.\s*$#s', '', $value);
    }
    return $value;
  }
}