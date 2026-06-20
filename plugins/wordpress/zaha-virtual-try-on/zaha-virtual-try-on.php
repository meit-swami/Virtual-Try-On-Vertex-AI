<?php
/**
 * Plugin Name: ZAHA Virtual Try-On
 * Plugin URI: https://github.com/Ashot72/Virtual-Try-On-Vertex-AI
 * Description: Add Virtual Try-On button to WooCommerce product pages. Customers redeem promo codes for try-on credits.
 * Version: 1.0.0
 * Author: ZAHA AI
 * Requires at least: 5.8
 * Requires PHP: 7.4
 * Text Domain: zaha-virtual-try-on
 */

if (!defined('ABSPATH')) {
    exit;
}

define('ZAHA_VTO_VERSION', '1.0.0');
define('ZAHA_VTO_PLUGIN_DIR', plugin_dir_path(__FILE__));

class Zaha_Virtual_Try_On {
    public function __construct() {
        add_action('admin_menu', [$this, 'admin_menu']);
        add_action('admin_init', [$this, 'register_settings']);
        add_action('wp_enqueue_scripts', [$this, 'enqueue_scripts']);
        add_action('woocommerce_single_product_summary', [$this, 'render_button'], 35);
        add_shortcode('zaha_try_on', [$this, 'shortcode']);
    }

    public function admin_menu(): void {
        add_options_page(
            'ZAHA Virtual Try-On',
            'ZAHA Try-On',
            'manage_options',
            'zaha-try-on',
            [$this, 'settings_page']
        );
    }

    public function register_settings(): void {
        register_setting('zaha_try_on', 'zaha_api_url', ['sanitize_callback' => 'esc_url_raw']);
        register_setting('zaha_try_on', 'zaha_api_key', ['sanitize_callback' => 'sanitize_text_field']);
        register_setting('zaha_try_on', 'zaha_button_text', ['sanitize_callback' => 'sanitize_text_field', 'default' => '✨ Virtual Try-On']);
    }

    public function settings_page(): void {
        if (!current_user_can('manage_options')) {
            return;
        }
        ?>
        <div class="wrap">
            <h1>ZAHA Virtual Try-On Settings</h1>
            <form method="post" action="options.php">
                <?php settings_fields('zaha_try_on'); ?>
                <table class="form-table">
                    <tr>
                        <th><label for="zaha_api_url">API URL</label></th>
                        <td>
                            <input type="url" id="zaha_api_url" name="zaha_api_url" value="<?php echo esc_attr(get_option('zaha_api_url', 'http://localhost:3000')); ?>" class="regular-text" />
                            <p class="description">Your ZAHA server URL (e.g. https://your-app.onrender.com or http://localhost:3000 for testing)</p>
                        </td>
                    </tr>
                    <tr>
                        <th><label for="zaha_api_key">API Key</label></th>
                        <td>
                            <input type="text" id="zaha_api_key" name="zaha_api_key" value="<?php echo esc_attr(get_option('zaha_api_key')); ?>" class="regular-text" />
                            <p class="description">From ZAHA admin → Promo Code Management → Plugin sites</p>
                        </td>
                    </tr>
                    <tr>
                        <th><label for="zaha_button_text">Button text</label></th>
                        <td>
                            <input type="text" id="zaha_button_text" name="zaha_button_text" value="<?php echo esc_attr(get_option('zaha_button_text', '✨ Virtual Try-On')); ?>" class="regular-text" />
                        </td>
                    </tr>
                </table>
                <?php submit_button(); ?>
            </form>
            <hr/>
            <h2>Shortcode</h2>
            <p>Use on any page: <code>[zaha_try_on product_url="https://yoursite.com/product/example"]</code></p>
        </div>
        <?php
    }

    public function enqueue_scripts(): void {
        $api_url = get_option('zaha_api_url');
        $api_key = get_option('zaha_api_key');
        if (!$api_url || !$api_key) {
            return;
        }

        wp_enqueue_script(
            'zaha-plugin',
            trailingslashit($api_url) . 'plugin.js',
            [],
            ZAHA_VTO_VERSION,
            true
        );

        $product_url = is_product() ? get_permalink() : '';
        $product_image = '';
        if (is_product()) {
            global $product;
            if ($product instanceof WC_Product) {
                $img_id = $product->get_image_id();
                if ($img_id) {
                    $product_image = wp_get_attachment_url($img_id);
                }
            }
        }

        wp_add_inline_script('zaha-plugin', sprintf(
            'document.addEventListener("DOMContentLoaded",function(){if(window.ZahaTryOn){ZahaTryOn.init({apiUrl:%s,apiKey:%s,productUrl:%s,productImage:%s,buttonText:%s,target:".zaha-try-on-wrap",position:"before"});}});',
            wp_json_encode($api_url),
            wp_json_encode($api_key),
            wp_json_encode($product_url),
            wp_json_encode($product_image),
            wp_json_encode(get_option('zaha_button_text', '✨ Virtual Try-On'))
        ));
    }

    public function render_button(): void {
        echo '<div class="zaha-try-on-wrap" data-zaha-try-on></div>';
    }

    public function shortcode($atts): string {
        $atts = shortcode_atts(['product_url' => ''], $atts);
        ob_start();
        echo '<div data-zaha-try-on data-product-url="' . esc_attr($atts['product_url']) . '"></div>';
        return ob_get_clean();
    }
}

new Zaha_Virtual_Try_On();
