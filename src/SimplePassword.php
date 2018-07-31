<?php

namespace primus852\SimplePassword;

class SimplePassword
{

    private static $length;
    private static $numbers;
    private static $special;
    private static $lower;
    private static $repeat;
    private static $ambiguous;
    private static $pw;
    private static $elapsed;
    private static $characters = array();
    private static $hadDuplicate = false;
    private static $roundsDuplicate = 0;
    private static $hadSpecial = false;
    private static $roundsSpecial = 0;

    const UPPERCASE = ['Q', 'W', 'E', 'R', 'T', 'Z', 'U', 'P', 'A', 'S', 'D', 'F', 'G', 'H', 'J', 'K', 'L', 'Y', 'X', 'C', 'V', 'B', 'N', 'M'];
    const LOWERCASE = ['q', 'w', 'e', 'r', 't', 'z', 'u', 'i', 'o', 'p', 'a', 's', 'd', 'f', 'g', 'h', 'j', 'k', 'y', 'x', 'c', 'v', 'b', 'n', 'm'];
    const NUMBERS = [2, 3, 4, 5, 6, 7, 8, 9];
    const SPECIALS = ['~', '!', '@', '#', '$', '%', '&', '*', '(', ')', '-', '_', '=', '+', '\\', '|', '/', '[', ']', '{', '}', '"', "'", ';', ':', '<', '>', ',', '.', '?'];
    const AMBIGUOUS = [0, 1, 'I', 'l', 'O'];

    /**
     * SimplePassword constructor.
     * @param int $length
     * @param int $numbers
     * @param int $special
     * @param bool $lower
     * @param bool $repeat
     * @param bool $ambiguous
     * @throws SimplePasswordException
     */
    public function __construct(int $length = 8, int $numbers = 2, int $special = 0, bool $lower = true, bool $repeat = true, bool $ambiguous = false)
    {

        /**
         * Debugging Stopwatch
         */
        $start = microtime(true);

        /* @var $length int */
        self::$length = $length;

        /* @var $numbers int */
        self::$numbers = $numbers;

        /* @var $special int */
        self::$special = $special;

        /* @var $lower bool */
        self::$lower = $lower;

        /* @var $repeat bool */
        self::$repeat = $repeat;

        /* @var $ambiguous bool */
        self::$ambiguous = $ambiguous;

        /**
         * Check if total length is not exceeded by min. numbers or min. specials
         */
        try {
            self::check();
        } catch (SimplePasswordException $e) {
            throw new SimplePasswordException($e->getMessage());
        }

        /**
         * Add Uppercase to available characters
         */
        self::$characters = array_merge(self::$characters, self::UPPERCASE);

        /**
         * Add Lowercase to available characters
         */
        self::$characters = self::$lower ? array_merge(self::$characters, self::LOWERCASE) : self::$characters;

        /**
         * Add ambiguous to available characters
         */
        self::$characters = self::$ambiguous ? array_merge(self::$characters, self::AMBIGUOUS) : self::$characters;

        self::$pw = self::generate();

        /**
         * Stop Stopwatch
         */
        self::$elapsed = microtime(true) - $start;

    }

    /**
     * @return string
     */
    private function generate(): string
    {

        /**
         * Init the mt_rand seed
         */
        mt_srand(crc32(microtime()));

        /**
         * Init Password String
         */
        $pw = '';

        $no_characters = self::$length - self::$numbers - self::$special;

        /**
         * Create the password with the regular characters
         */
        for ($c = 0; $c < $no_characters; $c++) {
            $pw .= self::$characters[mt_rand(0, count(self::$characters) - 1)];
        }

        /**
         * Add Numbers to password
         */
        if (self::$numbers > 0) {
            for ($n = 0; $n < self::$numbers; $n++) {
                $pw .= self::NUMBERS[mt_rand(0, count(self::NUMBERS) - 1)];
            }
        }

        /**
         * Add Special Characters to password
         */
        if (self::$special > 0) {
            for ($n = 0; $n < self::$special; $n++) {
                $pw .= self::SPECIALS[mt_rand(0, count(self::SPECIALS) - 1)];
            }
        }

        /**
         * Shuffle the final password, if the first character is a special character, shuffle again
         */
        $pw = self::first(str_shuffle(str_shuffle($pw)));


        /**
         * If no repeat characters are allowed, loop through it again and replace the duplicate
         */
        if (!self::$repeat) {

            $last = null;
            for ($i = 0; $i < strlen($pw); $i++) {

                if ($last !== null && $last === $pw{$i}) {
                    $pw{$i} = self::replace($pw{$i});
                }

                $last = $pw{$i};
            }
        }

        return $pw;

    }

    /**
     * @param $pw
     * @return string
     */
    private static function first($pw): string
    {

        /**
         * If Special characters are as much as total length, don't shuffle as it would go to infinity
         */
        if (self::$length === self::$special) {
            return $pw;
        }

        /**
         * Debugging
         */
        self::$hadSpecial = true;
        self::$roundsSpecial++;

        if (in_array(substr($pw, 0, 1), self::SPECIALS)) {
            $pw = str_shuffle($pw);
            return self::first($pw);
        }

        return $pw;
    }

    /**
     * @param string $character
     * @return mixed
     */
    private static function replace(string $character): string
    {

        /**
         * Debugging
         */
        self::$hadDuplicate = true;
        self::$roundsDuplicate++;

        if (in_array($character, self::NUMBERS)) {
            $new = self::NUMBERS[mt_rand(0, count(self::NUMBERS) - 1)];
        } elseif (in_array($character, self::SPECIALS)) {
            $new = self::SPECIALS[mt_rand(0, count(self::SPECIALS) - 1)];
        } else {
            $new = self::$characters[mt_rand(0, count(self::$characters) - 1)];
        }


        if ($new === $character) {
            return self::replace($new);
        }

        return $new;
    }

    /**
     * @throws SimplePasswordException
     */
    private function check()
    {

        /* @internal check if $numbers is bigger than $length */
        if (self::$numbers > self::$length) {
            throw new SimplePasswordException('No. of Numbers can\'t be longer than total length');
        }

        /* @internal check if $special is bigger than $length */
        if (self::$special > self::$length) {
            throw new SimplePasswordException('No. of Special Characters can\'t be longer than total length');
        }

        /* @internal check if $numbers + $special is bigger than $length */
        if ((self::$numbers + self::$special) > self::$length) {
            throw new SimplePasswordException('No. of Numbers + No. of Special Characters can\'t be longer than total length');
        }

    }

    /**
     * @return string
     */
    public static function pw(): string
    {
        return self::$pw;
    }

    /**
     * @return int
     * @throws SimplePasswordException
     */
    public static function strength() : int
    {
        if(self::$pw === null){
            throw new SimplePasswordException('No Password given to check');
        }

        return SimplePasswordStrength::checkScore(self::$pw);

    }

    /**
     * Return all input vars and resulting character set
     * @return array
     */
    public function debug(): array
    {

        return array(
            'characters' => self::$characters,
            'length' => self::$length,
            'numbers' => self::$numbers,
            'special' => self::$special,
            'lower' => self::$lower,
            'repeat' => self::$repeat,
            'ambiguous' => self::$ambiguous,
            'max' => count(self::$characters),
            'pw' => self::$pw,
            'repeat_found' => self::$hadDuplicate,
            'repeat_rounds' => self::$roundsDuplicate,
            'specials_first' => self::$hadSpecial,
            'specials_rounds' => self::$roundsSpecial,
            'elapsed' => number_format(self::$elapsed, 9) . 's',
        );

    }

}
