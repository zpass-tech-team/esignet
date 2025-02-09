import { useEffect, useRef, useState } from "react";
import LoadingIndicator from "../common/LoadingIndicator";
import FormAction from "./FormAction";
import { LoadingStates as states } from "../constants/states";
import { useTranslation } from "react-i18next";
import InputWithImage from "./InputWithImage";
import { buttonTypes, configurationKeys } from "../constants/clientConstants";
import ReCAPTCHA from "react-google-recaptcha";
import ErrorBanner from "../common/ErrorBanner";
import langConfigService from "../services/langConfigService";

const langConfig = await langConfigService.getEnLocaleConfiguration();  

export default function OtpGet({
  param,
  authService,
  openIDConnectService,
  onOtpSent,
  i18nKeyPrefix1 = "otp",
  i18nKeyPrefix2 = "errors"
}) {

  const { t: t1, i18n } = useTranslation("translation", {
    keyPrefix: i18nKeyPrefix1,
  });

  const { t: t2 } = useTranslation("translation", {
    keyPrefix: i18nKeyPrefix2,
  });

  const fields = param;
  let fieldsState = {};
  fields.forEach((field) => (fieldsState["Otp" + field.id] = ""));

  const post_SendOtp = authService.post_SendOtp;

  const commaSeparatedChannels =
    openIDConnectService.getEsignetConfiguration(configurationKeys.sendOtpChannels) ??
    process.env.REACT_APP_SEND_OTP_CHANNELS;

  const captchaEnableComponents =
    openIDConnectService.getEsignetConfiguration(configurationKeys.captchaEnableComponents) ??
    process.env.REACT_APP_CAPTCHA_ENABLE;

  const captchaEnableComponentsList = captchaEnableComponents
    .split(",")
    .map((x) => x.trim().toLowerCase());

  const [showCaptcha, setShowCaptcha] = useState(
    captchaEnableComponentsList.indexOf("otp") !== -1
  );

  const captchaSiteKey =
    openIDConnectService.getEsignetConfiguration(configurationKeys.captchaSiteKey) ??
    process.env.REACT_APP_CAPTCHA_SITE_KEY;

  const [loginState, setLoginState] = useState(fieldsState);
  const [status, setStatus] = useState({ state: states.LOADED, msg: "" });
  const [errorBanner, setErrorBanner] = useState(null);

  const [captchaToken, setCaptchaToken] = useState(null);
  const _reCaptchaRef = useRef(null);
  
  useEffect(() => {
    let loadComponent = async () => {
      i18n.on("languageChanged", function (lng) {
        if (showCaptcha) {
          //to rerender recaptcha widget on language change
          setShowCaptcha(false);
          setTimeout(() => {
            setShowCaptcha(true);
          }, 1);
        }
      });
    };

    loadComponent();
  }, []);

  const handleCaptchaChange = (value) => {
    setCaptchaToken(value);
  };

  const handleChange = (e) => {          
    let { id, value } = e.target;
    let cursorPosition = e.target.selectionStart;
    if (id === 'Otp_mosip-vid') {
        // Remove all slashes to reset the string before formatting
        value = value.replace(/[^\d]/g,"");
        // Add slashes based on the length of the value
        if (value.length > 6) {
            value = value.slice(0, 6) + '/' + value.slice(6);
            if(cursorPosition > 6) cursorPosition++;
        }
        if (value.length > 9) {
            value = value.slice(0, 9) + '/' + value.slice(9);
            if(cursorPosition > 9) cursorPosition++;
        }
        // Update the state with the formatted value
        setLoginState({ ...loginState, [id]: value }); 
        setTimeout(() => {
          e.target.setSelectionRange(cursorPosition, cursorPosition);
        }, 0);
  }
  };

  const sendOTP = async () => {
    try {

      let transactionId = openIDConnectService.getTransactionId();
      let vid = loginState["Otp_mosip-vid"];

      let otpChannels = commaSeparatedChannels.split(",").map((x) => x.trim());

      setStatus({ state: states.LOADING, msg: "sending_otp_msg" });
      const sendOtpResponse = await post_SendOtp(
        transactionId,
        vid,
        otpChannels,
        captchaToken
      );
      setStatus({ state: states.LOADED, msg: "" });

      const { response, errors } = sendOtpResponse;

      if (errors != null && errors.length > 0) {
        
        let errorCodeCondition = langConfig.errors.otp[errors[0].errorCode] !== undefined && langConfig.errors.otp[errors[0].errorCode] !== null;

        if (errorCodeCondition) {
          setErrorBanner({
            errorCode: `otp.${errors[0].errorCode}`,
            show: true
          });
        }
        else {
          setErrorBanner({
            errorCode: `${errors[0].errorCode}`,
            show: true
          });
        }
        return;
      } else {
        onOtpSent(vid, response);
        setErrorBanner(null);
      }
    } catch (error) {
      setErrorBanner({
        errorCode: "otp.send_otp_failed_msg",
        show: true
      });
      setStatus({ state: states.ERROR, msg: "" });
    }
  };

  const onCloseHandle = () => {
    setErrorBanner(null);
  };

  return (
    <>
      {errorBanner !== null && (
        <ErrorBanner
          showBanner={errorBanner.show}
          errorCode={t2(errorBanner.errorCode)}
          onCloseHandle={onCloseHandle}
        />
      )}

      <div className="mt-12">
        {fields.map((field) => (
          <InputWithImage
            key={"Otp_" + field.id}
            handleChange={handleChange}
            value={loginState["Otp_" + field.id]}
            labelText={t1(field.labelText)}
            labelFor={field.labelFor}
            id={"Otp_" + field.id}
            name={field.name}
            type={field.type}
            isRequired={field.isRequired}
            placeholder={t1(field.placeholder)}
            imgPath="images/photo_scan.png"
            tooltipMsg="vid_info"
          />
        ))}

        {showCaptcha && (
          <div className="flex justify-center mt-5 mb-5">
            <ReCAPTCHA
              hl={i18n.language}
              ref={_reCaptchaRef}
              onChange={handleCaptchaChange}
              sitekey={captchaSiteKey}
            />
          </div>
        )}

        <div className="mt-5 mb-5">
          <FormAction
            type={buttonTypes.button}
            text={t1("get_otp")}
            handleClick={sendOTP}
            id="get_otp"
            disabled={!loginState["Otp_mosip-vid"]?.trim() || (showCaptcha && captchaToken === null)}
          />
        </div>

        {status.state === states.LOADING && (
          <LoadingIndicator size="medium" message={status.msg} />
        )}
      </div>
    </>
  );
}
