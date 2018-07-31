<?php
/**
 * Created by PhpStorm.
 * User: torsten
 * Date: 31.07.2018
 * Time: 08:35
 */

namespace primus852\SimplePassword;


class SimplePasswordStrength
{

    const SCORE = array(
        'short' => 1,
        'min' => 2,
        'tooWeak' => 3,
        'weak' => 4,
        'fair' => 5,
        'medium' => 6,
        'strong' => 7,
        'veryStrong' => 8
    );

    /**
     * @param string $pw
     * @return int|mixed
     */
    public static function checkScore(string $pw)
    {

        /**
         * Initial Values
         */
        $score = 0;
        $numbers = 0;
        $special = 0;
        $lower = false;
        $duplicate = false;

        /**
         * Password is too short
         */
        if (strlen($pw) <= 6) {
            return self::SCORE['short'];
        }

        $score++;

        /**
         * Password 8+
         */
        if (strlen($pw) >= 8) {
            $score++;
        }

        /**
         * Password 10+
         */
        if (strlen($pw) >= 10) {
            $score++;
        }

        /**
         * Password 12+
         */
        if (strlen($pw) >= 12) {
            $score++;
        }

        /**
         * Password 16+
         */
        if (strlen($pw) >= 16) {
            $score++;
        }


        $last = null;
        for ($i = 0; $i < strlen($pw); $i++) {

            /**
             * Character is in NUMBERS or in AMBIGUOUS and an Integer
             */
            if(in_array($pw{$i}, SimplePassword::NUMBERS) || (in_array($pw{$i}, SimplePassword::AMBIGUOUS) && filter_var($pw{$i}, FILTER_VALIDATE_INT) === true)){
                $numbers++;
            }

            /**
             * Character is in SPECIALS
             */
            if(in_array($pw{$i}, SimplePassword::SPECIALS)){
                $special++;
            }

            /**
             * Character is in lowercase
             */
            if(ctype_lower($pw{$i})){
                $lower = true;
            }

            /**
             * Duplicate found
             */
            if ($last !== null && $last === $pw{$i}) {
                $duplicate = true;
            }

            $last = $pw{$i};

        }

        /**
         * Has Numbers
         */
        if ($numbers > 0) {
            $score++;
        }

        /**
         * Has Special Characters
         */
        if ($special > 0) {
            $score++;
        }

        /**
         * Has Lower Case
         */
        if ($lower) {
            $score++;
        }

        /**
         * Deduct if duplicate
         */
        if($duplicate){
            $score--;
        }

        return $score;

    }

}